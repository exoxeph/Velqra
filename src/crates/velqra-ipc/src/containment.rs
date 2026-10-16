// SPDX-License-Identifier: GPL-3.0-only
//! Windows directory leases. A lease denies rename/delete on every ancestor, not just the leaf.
use std::collections::HashMap;
use std::fs::File;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const MARKER: &str = ".velqra-directory-pin";
type MarkerSlot = Arc<Mutex<Option<MarkerEntry>>>;
static MARKERS: OnceLock<Mutex<HashMap<PathBuf, MarkerSlot>>> = OnceLock::new();
static CLEANUP_FAILURES: AtomicU64 = AtomicU64::new(0);

struct MarkerEntry {
    file: File,
    leases: usize,
}

struct MarkerLease {
    key: Option<(PathBuf, MarkerSlot)>,
}

fn markers() -> std::sync::MutexGuard<'static, HashMap<PathBuf, MarkerSlot>> {
    MARKERS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// Remove idle slots only when nobody can be waiting on the per-directory mutex. Acquire clones
// its slot under the registry lock, so it cannot race deletion into a different slot for this key.
fn prune_slot(key: &Path, slot: &MarkerSlot) {
    let mut registry = markers();
    if Arc::strong_count(slot) == 2 && registry.get(key).is_some_and(|s| Arc::ptr_eq(s, slot)) {
        registry.remove(key);
    }
}

impl MarkerLease {
    fn acquire(leaf: &File) -> io::Result<Self> {
        let key = final_path(leaf)?;
        let slot = {
            let mut registry = markers();
            registry
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(None)))
                .clone()
        };
        let result = (|| {
            let mut state = slot.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = state.as_mut() {
                verify_marker(&entry.file)?;
                entry.leases = entry
                    .leases
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("too many directory leases"))?;
            } else {
                let file = open_relative(leaf, std::ffi::OsStr::new(MARKER), false, true)?;
                verify_marker(&file)?;
                hide_marker(&file)?;
                *state = Some(MarkerEntry { file, leases: 1 });
            }
            Ok(())
        })();
        if let Err(error) = result {
            prune_slot(&key, &slot);
            return Err(error);
        }
        Ok(Self {
            key: Some((key, slot)),
        })
    }

    fn release_with(&mut self, delete: impl FnOnce(&File) -> io::Result<()>) {
        let Some((key, slot)) = self.key.take() else {
            return;
        };
        let failed = {
            let mut state = slot.lock().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = state.as_mut() else {
                return;
            };
            entry.leases -= 1;
            if entry.leases != 0 {
                return;
            }
            let entry = state.take().expect("registered marker");
            let failed = verify_marker(&entry.file)
                .and_then(|()| delete(&entry.file))
                .is_err();
            // Delete AND close serialize against the same directory, without the global mutex.
            drop(entry);
            failed
        };
        prune_slot(&key, &slot);
        if failed {
            let count = CLEANUP_FAILURES
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            // Best effort is synchronous and may block; no mutex is held while logging.
            // Never emit a path, URL or OS error string.
            use std::io::Write;
            let _ = writeln!(io::stderr(), "velqra marker_cleanup_failed count={count}");
        }
    }
}

impl Drop for MarkerLease {
    fn drop(&mut self) {
        self.release_with(delete_by_handle);
    }
}

fn verify_marker(file: &File) -> io::Result<()> {
    verify_kind(file, false)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() != 0 {
        return Err(io::Error::other("invalid directory marker"));
    }
    Ok(())
}

#[cfg(windows)]
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::*;

/// Kept until the caller has durably recorded the attempt's terminal outcome.
pub struct DirectoryLease {
    // Fields drop in declaration order: remove the marker BEFORE releasing directory pins.
    _marker: MarkerLease,
    _handles: Vec<File>,
    directory: PathBuf,
}

impl DirectoryLease {
    /// Pin existing ancestors first, then create/pin missing destination folders one at a time.
    /// No reparse component is accepted, including ancestors above `root`.
    pub fn acquire(root: &Path, directory: &Path) -> io::Result<Self> {
        Self::acquire_with_hook(root, directory, || {})
    }

    fn acquire_with_hook(
        root: &Path,
        directory: &Path,
        before_marker: impl FnOnce(),
    ) -> io::Result<Self> {
        Self::acquire_with_hooks(root, directory, before_marker, || {})
    }

    fn acquire_with_hooks(
        root: &Path,
        directory: &Path,
        before_marker: impl FnOnce(),
        after_marker: impl FnOnce(),
    ) -> io::Result<Self> {
        if !root.is_absolute()
            || !directory.starts_with(root)
            || directory
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(io::Error::other("invalid containment path"));
        }
        let mut handles = Vec::new();
        let mut path = PathBuf::new();
        let mut previous: Option<PathBuf> = None;
        for component in directory.components() {
            path.push(component);
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let handle = match (handles.last(), component) {
                (Some(parent), Component::Normal(name)) => {
                    open_relative(parent, name, true, path.starts_with(root))?
                }
                (None, Component::RootDir) => open_pinned(&path, true)?,
                _ => return Err(io::Error::other("invalid directory component")),
            };
            verify_kind(&handle, true)?;
            let resolved = final_path(&handle)?;
            if let Some(parent) = &previous {
                if resolved.parent() != Some(parent.as_path()) {
                    return Err(io::Error::other("directory identity changed"));
                }
            }
            previous = Some(resolved);
            handles.push(handle);
        }
        before_marker();
        let leaf = handles
            .last()
            .ok_or_else(|| io::Error::other("empty containment chain"))?;
        let marker = MarkerLease::acquire(leaf)?;
        after_marker();
        // Attribute-only handles can install a junction even while delete/write sharing is denied.
        // Relative creation never traverses that junction. Once the marker and child entries are
        // pinned, the directories cannot become empty; reject any conversion that won beforehand.
        for handle in &handles {
            verify_kind(handle, true)?;
        }
        Ok(Self {
            _marker: marker,
            _handles: handles,
            directory: directory.to_path_buf(),
        })
    }

    /// Pin the source object and rename it by handle without replacement. One operation moves
    /// the name, so failure cannot leave a published hard link plus an undeletable source.
    pub fn publish(&self, source: &Path, target: &Path) -> io::Result<()> {
        self.publish_inner(source, target, || {})
    }

    fn publish_inner(
        &self,
        source: &Path,
        target: &Path,
        before_rename: impl FnOnce(),
    ) -> io::Result<()> {
        if source.parent() != Some(self.directory.as_path())
            || target.parent() != Some(self.directory.as_path())
            || source == target
        {
            return Err(io::Error::other("publish outside lease"));
        }
        let source_handle = open_pinned(source, false)?;
        let parent = std::fs::canonicalize(&self.directory)?;
        if final_path(&source_handle)?.parent() != Some(parent.as_path()) {
            return Err(io::Error::other("source outside lease"));
        }
        before_rename();
        rename_by_handle(&source_handle, target)
    }
}

#[cfg(windows)]
fn rename_by_handle(file: &File, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = target.as_os_str().encode_wide().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let bytes = offset
        .checked_add((name.len() + 1) * 2)
        .filter(|n| *n <= u32::MAX as usize)
        .ok_or_else(|| io::Error::other("rename name too long"))?;
    // u64 storage supplies the alignment required by FILE_RENAME_INFO on Windows x64.
    let mut storage = vec![
        0u64;
        bytes
            .max(std::mem::size_of::<FILE_RENAME_INFO>())
            .div_ceil(8)
    ];
    // SAFETY: zeroed, aligned storage covers the full structure and variable-length UTF-16 name.
    // No references escape; the file owns a live DELETE-capable handle and the synchronous call
    // consumes exactly `bytes` initialized bytes. ReplaceIfExists=false forbids overwriting.
    let ok = unsafe {
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
            name.len(),
        );
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            bytes as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn rename_by_handle(_: &File, _: &Path) -> io::Result<()> {
    unreachable!()
}

#[cfg(windows)]
fn open_pinned(path: &Path, directory: bool) -> io::Result<File> {
    let access = if directory {
        FILE_GENERIC_READ
    } else {
        FILE_GENERIC_READ | 0x00010000
    }; // DELETE
    let file = OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE) // no delete sharing
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_kind(&file, directory)?;
    Ok(file)
}

#[cfg(windows)]
fn verify_kind(file: &File, directory: bool) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.is_dir() != directory
    {
        return Err(io::Error::other("reparse point or wrong object kind"));
    }
    Ok(())
}

#[cfg(windows)]
fn final_path(file: &File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; 32768];
    // SAFETY: the File owns a live handle; the writable buffer has the advertised capacity.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        return Err(io::Error::other("resolved path too long"));
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

#[cfg(windows)]
fn open_relative(
    parent: &File,
    name: &std::ffi::OsStr,
    directory: bool,
    create: bool,
) -> io::Result<File> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::{
        Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem as nt},
        Win32::{
            Foundation::{OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING},
            System::IO::IO_STATUS_BLOCK,
        },
    };
    if Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(io::Error::other("relative name required"));
    }
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let bytes = wide
        .len()
        .checked_mul(2)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or_else(|| io::Error::other("name too long"))?;
    let mut text = UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: bytes as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut text,
        Attributes: OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut result = IO_STATUS_BLOCK::default();
    let mut handle = std::ptr::null_mut();
    // SAFETY: parent is a live directory handle; attrs, its UNICODE_STRING and UTF-16 buffer remain
    // live for the synchronous call. Lengths are checked, one basename only. OPEN_REPARSE_POINT
    // and OBJ_DONT_REPARSE forbid following a substituted entry. No asynchronous handle is requested.
    let status = unsafe {
        nt::NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ
                | if directory {
                    0
                } else {
                    0x00010000 | FILE_WRITE_ATTRIBUTES
                },
            &attrs,
            &mut result,
            std::ptr::null(),
            if directory {
                FILE_ATTRIBUTE_NORMAL
            } else {
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            },
            // Marker content must not grow between verification and deletion. All concurrent
            // in-process leases share this handle through the registry rather than reopening it.
            if directory {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            if create {
                nt::FILE_OPEN_IF
            } else {
                nt::FILE_OPEN
            },
            nt::FILE_SYNCHRONOUS_IO_NONALERT
                | nt::FILE_OPEN_REPARSE_POINT
                | if directory {
                    nt::FILE_DIRECTORY_FILE
                } else {
                    nt::FILE_NON_DIRECTORY_FILE
                },
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "contained open refused ({status:#x})"
        )));
    }
    // SAFETY: successful NtCreateFile transferred one owned handle; no other owner will close it.
    let file = unsafe { File::from_raw_handle(handle) };
    verify_kind(&file, directory)?;
    Ok(file)
}

#[cfg(windows)]
fn hide_marker(file: &File) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let attrs = file.metadata()?.file_attributes();
    let info = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: (attrs & !FILE_ATTRIBUTE_NORMAL)
            | FILE_ATTRIBUTE_HIDDEN
            | FILE_ATTRIBUTE_SYSTEM,
    };
    // SAFETY: file owns a live WRITE_ATTRIBUTES-capable handle; info has the exact layout/size
    // required by FileBasicInfo and remains live during the synchronous call. Times are unchanged.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            &info as *const _ as *const _,
            std::mem::size_of_val(&info) as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn hide_marker(_: &File) -> io::Result<()> {
    unreachable!()
}

#[cfg(windows)]
fn delete_by_handle(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the source is a live DELETE-capable, non-reparse file handle; info is the correctly
    // sized structure for FileDispositionInfo and remains live for the synchronous call.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            &info as *const _ as *const _,
            std::mem::size_of_val(&info) as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn open_pinned(_: &Path, _: bool) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows containment required",
    ))
}
#[cfg(not(windows))]
fn final_path(_: &File) -> io::Result<PathBuf> {
    unreachable!()
}
#[cfg(not(windows))]
fn delete_by_handle(_: &File) -> io::Result<()> {
    unreachable!()
}

#[cfg(not(windows))]
fn verify_kind(_: &File, _: bool) -> io::Result<()> {
    unreachable!()
}
#[cfg(not(windows))]
fn open_relative(_: &File, _: &std::ffi::OsStr, _: bool, _: bool) -> io::Result<File> {
    unreachable!()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn slow_marker_cleanup_does_not_lock_unrelated_directories() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let mut lease = DirectoryLease::acquire(a.path(), a.path()).unwrap();
        let (entered_tx, entered_rx) = channel();
        let (release_tx, release_rx) = channel();
        let (other_tx, other_rx) = channel();
        let (same_tx, same_rx) = channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                lease._marker.release_with(|file| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    delete_by_handle(file)
                })
            });
            entered_rx.recv().unwrap();
            scope.spawn(|| {
                let other = DirectoryLease::acquire(b.path(), b.path()).unwrap();
                other_tx.send(()).unwrap();
                drop(other);
            });
            scope.spawn(|| {
                let same = DirectoryLease::acquire(a.path(), a.path()).unwrap();
                same_tx.send(()).unwrap();
                drop(same);
            });
            let unrelated_progress = other_rx.recv_timeout(Duration::from_secs(2)).is_ok();
            let same_waited = same_rx.try_recv().is_err();
            release_tx.send(()).unwrap();
            same_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(
                unrelated_progress,
                "slow cleanup held process-wide registry mutex"
            );
            assert!(
                same_waited,
                "same directory must serialize acquire against delete/close"
            );
        });
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn readonly_publication_never_leaves_two_names_on_failure() {
        let root = tempfile::tempdir().unwrap();
        let lease = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        let source = root.path().join("part");
        let target = root.path().join("final");
        std::fs::write(&source, b"payload").unwrap();
        let mut permissions = source.metadata().unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&source, permissions).unwrap();
        let result = lease.publish(&source, &target);
        let both = source.exists() && target.exists();
        // Always restore attributes before asserting so a RED run leaves no readonly residue.
        for p in [&source, &target] {
            if p.exists() {
                let mut perms = p.metadata().unwrap().permissions();
                perms.set_readonly(false);
                std::fs::set_permissions(p, perms).unwrap();
            }
        }
        assert!(!both, "publication returned {result:?} but left both names");
        if result.is_ok() {
            assert!(target.exists() && !source.exists());
        } else {
            assert!(source.exists() && !target.exists());
        }
    }

    #[test]
    fn marker_is_hidden_system_and_last_overlapping_lease_removes_it() {
        use std::os::windows::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".velqra-directory-pin");
        for _ in 0..3 {
            let first = DirectoryLease::acquire(root.path(), root.path()).unwrap();
            let marker = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&path)
                .unwrap();
            let attrs = marker.metadata().unwrap().file_attributes();
            assert_eq!(
                attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            );
            drop(marker);
            let second = DirectoryLease::acquire(root.path(), root.path()).unwrap();
            drop(first);
            assert!(path.exists(), "another lease still requires the marker");
            drop(second);
            assert!(!path.exists(), "last lease cleans up");
        }
    }

    #[test]
    fn marker_stale_empty_is_reused_but_hostile_entries_are_not_deleted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".velqra-directory-pin");
        // Simulate crash residue: an empty entry with no live process/registry ownership.
        std::fs::write(&path, b"").unwrap();
        let created = std::fs::metadata(&path).unwrap().created().unwrap();
        let lease = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        use std::os::windows::fs::MetadataExt;
        let slot = markers()[&final_path(lease._handles.last().unwrap()).unwrap()].clone();
        let attrs = slot
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .file
            .metadata()
            .unwrap()
            .file_attributes();
        assert_eq!(
            attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().created().unwrap(),
            created
        );
        drop(lease);
        assert!(!path.exists());
        std::fs::write(&path, b"user data").unwrap();
        assert!(DirectoryLease::acquire(root.path(), root.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"user data");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(DirectoryLease::acquire(root.path(), root.path()).is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn marker_same_named_junction_is_refused_and_left_untouched() {
        use std::os::windows::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = root.path().join(MARKER);
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&path)
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(DirectoryLease::acquire(root.path(), root.path()).is_err());
        assert_ne!(
            std::fs::symlink_metadata(&path).unwrap().file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(
            std::fs::canonicalize(&path).unwrap(),
            std::fs::canonicalize(outside.path()).unwrap()
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn marker_cleanup_failure_is_nonfatal_and_next_acquire_reuses_residue() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(MARKER);
        let mut lease = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        let before = CLEANUP_FAILURES.load(Ordering::Relaxed);
        lease
            ._marker
            .release_with(|_| Err(io::Error::other("injected deletion refusal")));
        assert!(CLEANUP_FAILURES.load(Ordering::Relaxed) > before);
        assert!(path.is_file());
        drop(lease); // No cleanup error escapes to the owner/terminal acknowledgement.
        let next = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        drop(next);
        assert!(!path.exists());
    }

    #[test]
    // Windows-only test: restore the readonly flag on our own temporary file, not Unix modes.
    #[allow(clippy::permissions_set_readonly_false)]
    fn marker_real_readonly_deletion_failure_is_nonfatal() {
        use std::os::windows::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(MARKER);
        let lease = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        let before = CLEANUP_FAILURES.load(Ordering::Relaxed);
        drop(lease);
        assert!(CLEANUP_FAILURES.load(Ordering::Relaxed) > before);
        assert!(path.exists());
        assert_ne!(
            std::fs::metadata(&path).unwrap().file_attributes() & FILE_ATTRIBUTE_HIDDEN,
            0
        );
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        drop(DirectoryLease::acquire(root.path(), root.path()).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn marker_cannot_grow_or_be_replaced_while_leased() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(MARKER);
        let lease = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        assert!(OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .is_err());
        assert!(std::fs::remove_file(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        drop(lease);
        assert!(!path.exists());
    }

    #[test]
    fn marker_concurrent_acquire_release_never_loses_a_live_pin() {
        let root = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(6);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                let root = root.path();
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..40 {
                        let lease = DirectoryLease::acquire(root, root).unwrap();
                        assert!(root.join(MARKER).is_file());
                        std::thread::yield_now();
                        drop(lease);
                    }
                });
            }
        });
        assert!(!root.path().join(MARKER).exists());
        let handle = open_pinned(root.path(), true).unwrap();
        assert!(!markers().contains_key(&final_path(&handle).unwrap()));
    }

    #[test]
    fn lease_blocks_in_place_reparse_conversion_not_only_renames() {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        fn ioctl(file: &File, code: u32, buffer: &mut [u8], write: bool) -> bool {
            let mut count = 0;
            // SAFETY: all handles are owned Files; the live byte buffer is passed with its length
            // as input OR output. No overlapped operation; count is a live writable u32.
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    code,
                    if write {
                        buffer.as_ptr().cast()
                    } else {
                        std::ptr::null()
                    },
                    if write { buffer.len() as u32 } else { 0 },
                    if write {
                        std::ptr::null_mut()
                    } else {
                        buffer.as_mut_ptr().cast()
                    },
                    if write { 0 } else { buffer.len() as u32 },
                    &mut count,
                    std::ptr::null_mut(),
                ) != 0
            }
        }
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let template = d.path().join("template");
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&template)
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(out.status.success());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&template)
            .unwrap();
        let mut buffer = vec![0u8; 16384];
        assert!(ioctl(&file, 0x900A8, &mut buffer, false)); // FSCTL_GET_REPARSE_POINT
        let size = u16::from_le_bytes([buffer[4], buffer[5]]) as usize + 8;
        buffer.truncate(size);
        drop(file);
        let cat = d.path().join("category");
        std::fs::create_dir(&cat).unwrap();
        // Positive control: the same buffer can convert an unleased, empty directory.
        let writable = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&cat)
            .unwrap();
        assert!(ioctl(&writable, 0x900A4, &mut buffer, true)); // FSCTL_SET_REPARSE_POINT
        drop(writable);
        std::fs::remove_dir(&cat).unwrap();
        std::fs::create_dir(&cat).unwrap();
        let lease = DirectoryLease::acquire(d.path(), &cat).unwrap();
        assert!(std::fs::remove_file(cat.join(".velqra-directory-pin")).is_err());
        // A read-only handle must not be sufficient to convert a pinned directory.
        let readable = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&cat)
            .unwrap();
        assert!(!ioctl(&readable, 0x900A4, &mut buffer, true));
        let writable = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&cat);
        let writable = writable.unwrap();
        assert!(
            !ioctl(&writable, 0x900A4, &mut buffer, true),
            "nonempty pinned directory must refuse in-place conversion"
        );
        drop(lease);
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        let empty = d.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        let result = DirectoryLease::acquire_with_hooks(
            d.path(),
            &empty,
            || {
                let attributes = OpenOptions::new()
                    .access_mode(FILE_WRITE_ATTRIBUTES)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&empty)
                    .unwrap();
                assert!(
                    ioctl(&attributes, 0x900A4, &mut buffer, true),
                    "prove a real in-place race, no rename"
                );
            },
            || {
                assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0,
                "relative marker open must not create outside, even before failed-acquire cleanup");
            },
        );
        assert!(
            result.is_err(),
            "conversion must refuse before engine submission"
        );
        assert_eq!(
            std::fs::read_dir(outside.path()).unwrap().count(),
            0,
            "relative marker creation must not follow the junction"
        );
    }

    #[test]
    fn source_entry_is_pinned_before_handle_rename() {
        let root = tempfile::tempdir().unwrap();
        let lease = DirectoryLease::acquire(root.path(), root.path()).unwrap();
        let source = root.path().join("part");
        let target = root.path().join("final");
        std::fs::write(&source, b"ours").unwrap();
        lease
            .publish_inner(&source, &target, || {
                assert!(std::fs::rename(&source, root.path().join("moved")).is_err());
                assert!(std::fs::remove_file(&source).is_err());
            })
            .unwrap();
        assert!(!source.exists());
        assert_eq!(std::fs::read(target).unwrap(), b"ours");
    }

    #[test]
    fn root_ancestor_and_category_junctions_are_rejected_by_the_handle_layer() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(DirectoryLease::acquire(&link, &link).is_err());
        assert!(DirectoryLease::acquire(d.path(), &link).is_err());
        std::fs::create_dir(real.join("child")).unwrap();
        assert!(DirectoryLease::acquire(&link.join("child"), &link.join("child")).is_err());
    }
}
