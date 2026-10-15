// SPDX-License-Identifier: GPL-3.0-only
//! Protection around the engine's first write and its final result (review 26b gate for Group C).
//!
//! Prepare checked the destination long before aria2 writes to it, and a path check followed by a
//! path-based write can always lose a race to a folder that is swapped for a junction in between.
//! aria2 writes by path, so the race cannot be closed from here; what this guard does is shrink and
//! then surface it: the folder is created by us immediately before the submit (a folder we just made
//! cannot already be a link), the destination is re-checked for links, and once the engine reports
//! the file exists or is complete the real location is checked again. A violation cancels the task
//! and is reported as a failed transfer, never as success.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use velqra_core::path_policy::finalize_check;
use velqra_core::{Engine, EngineError, EngineRequest, EngineStatus, Poll};

/// Suffix of the file the engine writes while a download is incomplete.
const PART_SUFFIX: &str = ".velqra-part";

/// The final name and the partial name of one task.
struct Paths {
    final_path: PathBuf,
    part: PathBuf,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// Names for which an HTML body is a perfectly good result.
fn html_is_expected(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext {
        None => true, // no extension says nothing about the expected type
        Some(e) => matches!(
            e.as_str(),
            "html"
                | "htm"
                | "xhtml"
                | "shtml"
                | "txt"
                | "md"
                | "xml"
                | "svg"
                | "php"
                | "asp"
                | "aspx"
                | "jsp"
                | "json"
                | "csv"
                | "log"
        ),
    }
}

/// True when the start of the file is an HTML document: a login or error page that the server sent
/// with a 200 instead of the file that was asked for.
fn looks_like_html(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 512];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let mut bytes = &head[..n];
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        bytes = &bytes[3..];
    }
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    let lower: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    let tag = |name: &[u8]| {
        lower.starts_with(name)
            && matches!(
                lower.get(name.len()),
                Some(b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')
            )
    };
    // the tags a login, error or block page opens with
    const OPENERS: [&[u8]; 10] = [
        b"<html", b"<head", b"<body", b"<meta", b"<title", b"<script", b"<style", b"<form",
        b"<div", b"<table",
    ];
    if lower.starts_with(b"<!doctype html")
        || lower.starts_with(b"<!--")
        || OPENERS.iter().any(|t| tag(t))
    {
        return true;
    }
    // an XHTML page that opens with an XML declaration
    lower.starts_with(b"<?xml") && lower.windows(6).any(|w| w == b"<html " || w == b"<html>")
}

/// Moves `part` and its aria2 control file to `<part>.stale-N` names that are not in use, without
/// ever replacing anything (a hard link fails when the name exists).
fn isolate_stale(part: &Path) -> std::io::Result<()> {
    let control = with_suffix(part, ".aria2");
    let part_there = std::fs::symlink_metadata(part).is_ok();
    let control_there = std::fs::symlink_metadata(&control).is_ok();
    if !part_there && !control_there {
        return Ok(());
    }
    for n in 1..=9999u32 {
        let stale = with_suffix(part, &format!(".stale-{n}"));
        let stale_control = with_suffix(&stale, ".aria2");
        if std::fs::symlink_metadata(&stale).is_ok()
            || std::fs::symlink_metadata(&stale_control).is_ok()
        {
            continue;
        }
        if part_there {
            std::fs::hard_link(part, &stale)?;
            std::fs::remove_file(part)?;
        }
        if control_there {
            std::fs::hard_link(&control, &stale_control)?;
            std::fs::remove_file(&control)?;
        }
        return Ok(());
    }
    Err(std::io::Error::other("too many stale files"))
}

pub struct Guarded<E: Engine> {
    inner: E,
    root: PathBuf,
    destinations: HashMap<String, Paths>,
    violated: HashSet<String>,
    published: HashSet<String>,
    /// Test-only: runs between the last check and the publish, to model a folder swapped there.
    #[cfg(test)]
    before_publish: Option<Box<dyn FnMut()>>,
}

impl<E: Engine> Guarded<E> {
    pub fn new(inner: E, root: PathBuf) -> Self {
        Self {
            inner,
            root,
            destinations: HashMap::new(),
            violated: HashSet::new(),
            published: HashSet::new(),
            #[cfg(test)]
            before_publish: None,
        }
    }

    pub fn inner(&mut self) -> &mut E {
        &mut self.inner
    }

    /// True when `path` is still a plain location under the root.
    fn still_inside(&self, path: &Path) -> bool {
        finalize_check(&self.root, path).is_ok()
    }

    /// Looks again at a task the engine says is running or finished. `Some` is a verdict that
    /// replaces the engine's: Failed for a wrong place or a refused publish, Done after publishing.
    /// `None` means nothing to add (or an attempt this guard never submitted).
    fn check(&mut self, attempt: &str, done: bool) -> Option<EngineStatus> {
        let (final_path, part) = self
            .destinations
            .get(attempt)
            .map(|p| (p.final_path.clone(), p.part.clone()))?;
        if !self.still_inside(&part) {
            self.violation(attempt);
            return Some(EngineStatus::Failed("transfer failed".into()));
        }
        if !done {
            return None;
        }
        // A server that answers 200 with its login or error page has not delivered the file.
        if !html_is_expected(&final_path) && looks_like_html(&part) {
            self.violated.insert(attempt.to_string());
            return Some(EngineStatus::Failed("transfer failed".into()));
        }
        // Publish: a hard link fails if the final name exists, so a file that appeared meanwhile is
        // never replaced; only then is the part name dropped.
        #[cfg(test)]
        if let Some(hook) = self.before_publish.as_mut() {
            hook();
        }
        match std::fs::hard_link(&part, &final_path) {
            Ok(()) => {
                // The link was made by path, so look again: only a final name that is still a plain
                // place under the root counts. Nothing is removed unless it is, because the part
                // name may by now lead somewhere that is not ours.
                if !self.still_inside(&final_path) {
                    self.violated.insert(attempt.to_string());
                    return Some(EngineStatus::Failed("transfer failed".into()));
                }
                let _ = std::fs::remove_file(&part);
                self.published.insert(attempt.to_string());
                Some(EngineStatus::Done)
            }
            Err(_) => {
                // the finished bytes stay in the part file, nothing is deleted
                self.violated.insert(attempt.to_string());
                Some(EngineStatus::Failed("transfer failed".into()))
            }
        }
    }

    fn violation(&mut self, attempt: &str) {
        if self.violated.insert(attempt.to_string()) {
            let _ = self.inner.cancel(attempt);
        }
    }
}

impl<E: Engine> Engine for Guarded<E> {
    fn submit(&mut self, request: &EngineRequest) -> Result<(), EngineError> {
        let Some(dest) = request.destination.as_deref().map(PathBuf::from) else {
            return Err(EngineError::Rejected);
        };
        let Some(parent) = dest.parent() else {
            return Err(EngineError::Rejected);
        };
        // before anything exists: the path must be a plain place under the root
        if !self.still_inside(&dest) {
            return Err(EngineError::Rejected);
        }
        // we make the folder ourselves right now, then look again: a folder created a moment ago
        // by this process cannot already have been a link, and an existing one is checked as it is
        std::fs::create_dir_all(parent).map_err(|_| EngineError::Rejected)?;
        if !self.still_inside(&dest) {
            return Err(EngineError::Rejected);
        }
        if std::fs::symlink_metadata(&dest).is_ok() {
            return Err(EngineError::Rejected);
        }
        // The engine writes a part file, so an incomplete download never sits under the final name.
        let part = with_suffix(&dest, PART_SUFFIX);
        // A partial download from an earlier run is never resumed: aria2 cannot prove the bytes at the
        // server are still the ones it saved, and resuming over changed bytes would mix two files.
        // It is set aside under a new name (never deleted; cleanup is a visible action) and this
        // download starts from zero.
        // Only when the engine positively does not know the task: a task it is running right now owns
        // its part file, and a question it cannot answer is no licence to move anything.
        if self.inner.status(&request.attempt) == Ok(EngineStatus::Unknown) {
            isolate_stale(&part).map_err(|_| EngineError::Rejected)?;
        }
        let mut forwarded = request.clone();
        forwarded.destination = Some(part.to_string_lossy().into_owned());
        self.destinations.insert(
            request.attempt.clone(),
            Paths {
                final_path: dest,
                part,
            },
        );
        self.inner.submit(&forwarded)
    }

    fn finished(&mut self, attempt: &str) -> Option<bool> {
        match self.status(attempt) {
            Ok(EngineStatus::Done) => Some(true),
            Ok(EngineStatus::Failed(_)) => Some(false),
            _ => None,
        }
    }

    fn status(&mut self, attempt: &str) -> Result<EngineStatus, EngineError> {
        if self.violated.contains(attempt) {
            return Ok(EngineStatus::Failed("transfer failed".into()));
        }
        if self.published.contains(attempt) {
            return Ok(EngineStatus::Done);
        }
        let status = self.inner.status(attempt)?;
        if matches!(status, EngineStatus::Active { .. } | EngineStatus::Done) {
            if let Some(settled) = self.check(attempt, status == EngineStatus::Done) {
                return Ok(settled);
            }
        }
        Ok(status)
    }

    fn poll(&mut self, attempt: &str) -> Poll {
        if self.violated.contains(attempt) {
            return Poll::Failed;
        }
        if self.published.contains(attempt) {
            return Poll::Done;
        }
        match self.inner.poll(attempt) {
            Poll::Running => match self.check(attempt, false) {
                Some(_) => Poll::Failed,
                None => Poll::Running,
            },
            Poll::Done => match self.check(attempt, true) {
                Some(EngineStatus::Failed(_)) => Poll::Failed,
                _ => Poll::Done,
            },
            other => other,
        }
    }

    fn has_forgotten(&mut self, attempt: &str) -> bool {
        self.inner.has_forgotten(attempt)
    }

    fn pause(&mut self, attempt: &str) -> Result<(), EngineError> {
        self.inner.pause(attempt)
    }

    fn resume(&mut self, attempt: &str) -> Result<(), EngineError> {
        self.inner.resume(attempt)
    }

    fn cancel(&mut self, attempt: &str) -> Result<(), EngineError> {
        self.inner.cancel(attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// An engine that "writes" the file as soon as it is submitted and says what it was told.
    #[derive(Default, Clone)]
    struct Probe {
        log: Rc<RefCell<Vec<String>>>,
        state: Rc<RefCell<Option<EngineStatus>>>,
    }

    impl Engine for Probe {
        fn submit(&mut self, r: &EngineRequest) -> Result<(), EngineError> {
            self.log.borrow_mut().push(format!("submit {}", r.attempt));
            if let Some(d) = &r.destination {
                let _ = std::fs::write(d, b"payload");
            }
            *self.state.borrow_mut() = Some(EngineStatus::Active { done: 1, total: 2 });
            Ok(())
        }
        fn finished(&mut self, _: &str) -> Option<bool> {
            match *self.state.borrow() {
                Some(EngineStatus::Done) => Some(true),
                Some(EngineStatus::Failed(_)) => Some(false),
                _ => None,
            }
        }
        fn status(&mut self, _: &str) -> Result<EngineStatus, EngineError> {
            Ok(self.state.borrow().clone().unwrap_or(EngineStatus::Unknown))
        }
        fn cancel(&mut self, a: &str) -> Result<(), EngineError> {
            self.log.borrow_mut().push(format!("cancel {a}"));
            Ok(())
        }
    }

    fn request(dest: &Path) -> EngineRequest {
        EngineRequest {
            attempt: "t1-g1".into(),
            url: "https://x.test/a".into(),
            filename: "a.zip".into(),
            context_ref: None,
            destination: Some(dest.to_string_lossy().into_owned()),
            context: None,
        }
    }

    fn part_of(dest: &Path) -> PathBuf {
        let mut os = dest.as_os_str().to_os_string();
        os.push(".velqra-part");
        PathBuf::from(os)
    }

    fn junction(link: &Path, target: &Path) {
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    #[test]
    fn the_folder_is_made_under_the_root_and_a_normal_download_passes_untouched() {
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Compressed").join("a.zip");
        g.submit(&request(&dest)).unwrap();
        assert!(part_of(&dest).exists(), "the engine writes the part file");
        assert!(
            !dest.exists(),
            "the final name does not exist while it downloads"
        );
        assert_eq!(probe.log.borrow().as_slice(), ["submit t1-g1"]);
        assert!(matches!(g.status("t1-g1"), Ok(EngineStatus::Active { .. })));
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        assert_eq!(g.status("t1-g1"), Ok(EngineStatus::Done));
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"payload",
            "published under the final name"
        );
        assert!(
            !part_of(&dest).exists(),
            "the part file is gone after publishing"
        );
        assert_eq!(g.finished("t1-g1"), Some(true));
        assert_eq!(probe.log.borrow().len(), 1, "no cancel for an honest task");
    }

    #[test]
    fn a_destination_outside_the_root_or_without_one_is_rejected_before_the_engine_sees_it() {
        let d = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let outside = other.path().join("a.zip");
        assert_eq!(g.submit(&request(&outside)), Err(EngineError::Rejected));
        let mut none = request(&outside);
        none.destination = None;
        assert_eq!(g.submit(&none), Err(EngineError::Rejected));
        let sneaky = d.path().join("x").join("..").join("..").join("a.zip");
        assert_eq!(g.submit(&request(&sneaky)), Err(EngineError::Rejected));
        // a refusal must not first create folders where it should not
        let deep = other.path().join("fresh").join("deeper").join("a.zip");
        assert_eq!(g.submit(&request(&deep)), Err(EngineError::Rejected));
        assert!(
            !other.path().join("fresh").exists(),
            "a folder was made outside the root"
        );
        assert!(probe.log.borrow().is_empty());
        assert!(!outside.exists());
    }

    #[test]
    fn a_category_folder_that_is_already_a_junction_is_refused_and_nothing_is_written_through_it() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        junction(&d.path().join("Compressed"), elsewhere.path());
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Compressed").join("a.zip");
        assert_eq!(g.submit(&request(&dest)), Err(EngineError::Rejected));
        assert!(probe.log.borrow().is_empty());
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }

    #[test]
    fn an_existing_destination_file_is_never_handed_to_the_engine() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("Compressed")).unwrap();
        let dest = d.path().join("Compressed").join("a.zip");
        std::fs::write(&dest, b"mine").unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        assert_eq!(g.submit(&request(&dest)), Err(EngineError::Rejected));
        assert!(probe.log.borrow().is_empty());
        assert_eq!(std::fs::read(&dest).unwrap(), b"mine");
    }

    #[test]
    fn a_folder_swapped_for_a_junction_after_the_submit_is_caught_and_the_task_is_cancelled_once() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Compressed").join("a.zip");
        g.submit(&request(&dest)).unwrap();
        // the engine's first write lands after this swap: model it by swapping, then writing outside
        std::fs::remove_file(part_of(&dest)).unwrap();
        std::fs::remove_dir(d.path().join("Compressed")).unwrap();
        junction(&d.path().join("Compressed"), elsewhere.path());
        std::fs::write(elsewhere.path().join("a.zip.velqra-part"), b"escaped").unwrap();
        for _ in 0..3 {
            assert_eq!(
                g.status("t1-g1"),
                Ok(EngineStatus::Failed("transfer failed".into()))
            );
        }
        assert_eq!(g.finished("t1-g1"), Some(false));
        // putting the folder back must not turn the verdict into success later
        std::fs::remove_dir(d.path().join("Compressed")).unwrap();
        std::fs::create_dir(d.path().join("Compressed")).unwrap();
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        assert_eq!(
            g.status("t1-g1"),
            Ok(EngineStatus::Failed("transfer failed".into()))
        );
        let cancels = probe
            .log
            .borrow()
            .iter()
            .filter(|l| l.starts_with("cancel"))
            .count();
        assert_eq!(cancels, 1, "cancelled exactly once, not on every poll");
    }

    #[test]
    fn a_task_that_finished_in_the_wrong_place_is_never_reported_as_done() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        std::fs::remove_file(part_of(&dest)).unwrap();
        std::fs::remove_dir(d.path().join("Other")).unwrap();
        junction(&d.path().join("Other"), elsewhere.path());
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        assert_eq!(
            g.status("t1-g1"),
            Ok(EngineStatus::Failed("transfer failed".into()))
        );
        assert_eq!(g.finished("t1-g1"), Some(false));
    }

    #[test]
    fn the_request_the_engine_receives_names_the_part_file_not_the_final_name() {
        struct Spy(Rc<RefCell<Option<String>>>);
        impl Engine for Spy {
            fn submit(&mut self, r: &EngineRequest) -> Result<(), EngineError> {
                *self.0.borrow_mut() = r.destination.clone();
                Ok(())
            }
            fn finished(&mut self, _: &str) -> Option<bool> {
                None
            }
        }
        let d = tempfile::tempdir().unwrap();
        let seen = Rc::new(RefCell::new(None));
        let mut g = Guarded::new(Spy(seen.clone()), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        assert_eq!(
            seen.borrow().as_deref(),
            Some(part_of(&dest).to_string_lossy().as_ref())
        );
    }

    #[test]
    fn publishing_never_replaces_a_file_that_appeared_under_the_final_name() {
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        std::fs::write(&dest, b"theirs").unwrap(); // someone else made the final name meanwhile
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        assert_eq!(
            g.status("t1-g1"),
            Ok(EngineStatus::Failed("transfer failed".into()))
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"theirs",
            "their file is untouched"
        );
        assert!(
            part_of(&dest).exists(),
            "the finished download is kept, not deleted"
        );
    }

    fn finish_with(content: &[u8], name: &str) -> (Result<EngineStatus, EngineError>, PathBuf) {
        let d = tempfile::tempdir().unwrap().keep();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.clone());
        let dest = d.join("Other").join(name);
        let mut req = request(&dest);
        req.attempt = "h1".into();
        g.submit(&req).unwrap();
        std::fs::write(part_of(&dest), content).unwrap();
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        (g.status("h1"), dest)
    }

    #[test]
    fn an_html_page_saved_under_a_binary_name_is_not_a_finished_download() {
        let page: &[&[u8]] = &[
            b"<!DOCTYPE html><html><body>Sign in</body></html>",
            b"<html><head></head>",
            b"\xEF\xBB\xBF  \r\n\t<!doctype HTML>",
            b"\n\n<HTML lang=en>",
            b"<head><title>x</title></head>",
            b"<body onload=x>",
            b"<meta charset=utf-8><title>x</title>",
            b"<title>Sign in</title>",
            b"<!-- cached --><div id=app>",
            b"<script>location='/login'</script>",
            b"<style>body{}</style><form action=/login>",
            b"  <table><tr><td>denied</td></tr></table>",
            b"<DIV class=error>Forbidden</DIV>",
            b"<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\">",
        ];
        for p in page {
            for name in ["a.zip", "setup.exe", "movie.mp4", "doc.pdf", "disk.iso"] {
                let (st, dest) = finish_with(p, name);
                assert_eq!(
                    st,
                    Ok(EngineStatus::Failed("transfer failed".into())),
                    "{name}: {}",
                    String::from_utf8_lossy(p)
                );
                assert!(!dest.exists(), "nothing under the final name");
                assert!(part_of(&dest).exists(), "the bytes are kept for inspection");
            }
        }
    }

    #[test]
    fn html_is_fine_when_the_user_asked_for_a_text_like_file_and_binaries_are_not_misread() {
        for name in [
            "page.html",
            "page.HTM",
            "a.xhtml",
            "notes.txt",
            "data.xml",
            "x.php",
            "noextension",
        ] {
            let (st, dest) = finish_with(b"<!DOCTYPE html><html>ok</html>", name);
            assert_eq!(st, Ok(EngineStatus::Done), "{name}");
            assert!(dest.exists());
        }
        let not_html: &[&[u8]] = &[
            b"PK\x03\x04 zip bytes",
            b"MZ\x90\x00 an exe",
            b"<htmlish but not a tag",
            b"<headline>",
            b"<bodybuilder>",
            b"<metadata-of-a-format>",
            b"<scripture>",
            b"<divider>",
            b"<titles>",
            b"<!-",
            b"",
            b"<",
            b"text <html> later in the file",
        ];
        for p in not_html {
            let (st, dest) = finish_with(p, "a.zip");
            assert_eq!(st, Ok(EngineStatus::Done), "{}", String::from_utf8_lossy(p));
            assert!(dest.exists());
        }
    }

    #[test]
    fn asking_again_after_publishing_still_says_done() {
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        for _ in 0..3 {
            assert_eq!(g.status("t1-g1"), Ok(EngineStatus::Done));
            assert_eq!(g.finished("t1-g1"), Some(true));
        }
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    }

    fn stale_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name().to_string_lossy().contains(".stale-"))
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_leftover_partial_download_is_isolated_never_resumed_and_never_deleted() {
        // aria2 cannot prove the bytes at the server are still the ones it saved, so a partial from
        // an earlier run is set aside and the download starts from zero
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("Other")).unwrap();
        let dest = d.path().join("Other").join("a.bin");
        std::fs::write(part_of(&dest), b"old partial").unwrap();
        let mut control = part_of(&dest).into_os_string();
        control.push(".aria2");
        std::fs::write(&control, b"old control").unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        assert_eq!(g.submit(&request(&dest)), Ok(()));
        assert_eq!(probe.log.borrow().as_slice(), ["submit t1-g1"]);
        let stale = stale_files(&d.path().join("Other"));
        assert_eq!(stale.len(), 2, "{stale:?}");
        assert!(stale
            .iter()
            .any(|(n, b)| n.ends_with(".aria2") && b == b"old control"));
        assert!(stale
            .iter()
            .any(|(n, b)| !n.ends_with(".aria2") && b == b"old partial"));
        assert_eq!(
            std::fs::read(part_of(&dest)).unwrap(),
            b"payload",
            "the engine started a fresh part file"
        );
    }

    #[test]
    fn submitting_a_task_the_engine_is_already_running_never_touches_its_live_part_file() {
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        g.submit(&request(&dest)).unwrap(); // the same attempt again
        assert!(part_of(&dest).exists(), "the live part file is still there");
        assert!(stale_files(&d.path().join("Other")).is_empty());
        // and if the engine cannot be asked, nothing is moved either
        struct Mute;
        impl Engine for Mute {
            fn submit(&mut self, _: &EngineRequest) -> Result<(), EngineError> {
                Err(EngineError::ReplyLost)
            }
            fn finished(&mut self, _: &str) -> Option<bool> {
                None
            }
            fn status(&mut self, _: &str) -> Result<EngineStatus, EngineError> {
                Err(EngineError::ReplyLost)
            }
        }
        std::fs::write(part_of(&dest), b"growing").unwrap();
        let mut g = Guarded::new(Mute, d.path().to_path_buf());
        let _ = g.submit(&request(&dest));
        assert_eq!(std::fs::read(part_of(&dest)).unwrap(), b"growing");
        assert!(stale_files(&d.path().join("Other")).is_empty());
    }

    #[test]
    fn a_leftover_part_file_without_a_control_file_is_isolated_too_and_repeats_get_new_names() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("Other")).unwrap();
        let dest = d.path().join("Other").join("a.bin");
        for round in 0..3u8 {
            std::fs::write(part_of(&dest), [b'0' + round]).unwrap();
            let mut g = Guarded::new(Probe::default(), d.path().to_path_buf());
            assert_eq!(g.submit(&request(&dest)), Ok(()));
            std::fs::remove_file(part_of(&dest)).unwrap(); // the probe's own file
        }
        let stale = stale_files(&d.path().join("Other"));
        let contents: Vec<_> = stale.iter().map(|(_, b)| b.clone()).collect();
        assert_eq!(
            contents,
            vec![b"0".to_vec(), b"1".to_vec(), b"2".to_vec()],
            "{stale:?}"
        );
    }

    #[test]
    fn poll_gives_the_same_verdicts_as_status_with_one_question() {
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        assert_eq!(g.poll("t1-g1"), Poll::Running);
        assert!(!dest.exists());
        *probe.state.borrow_mut() = Some(EngineStatus::Interrupted);
        assert_eq!(
            g.poll("t1-g1"),
            Poll::Interrupted,
            "passed through untouched"
        );
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        assert_eq!(g.poll("t1-g1"), Poll::Done);
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"payload",
            "published by poll"
        );
        assert!(!part_of(&dest).exists());
        assert_eq!(g.poll("t1-g1"), Poll::Done, "and stays done");
        assert_eq!(probe.log.borrow().len(), 1);
    }

    #[test]
    fn poll_refuses_html_and_a_swapped_folder_and_a_taken_final_name() {
        // html under a binary name
        let (st, dest) = {
            let d = tempfile::tempdir().unwrap().keep();
            let probe = Probe::default();
            let mut g = Guarded::new(probe.clone(), d.clone());
            let dest = d.join("Other").join("a.zip");
            g.submit(&request(&dest)).unwrap();
            std::fs::write(part_of(&dest), b"<html>login</html>").unwrap();
            *probe.state.borrow_mut() = Some(EngineStatus::Done);
            (g.poll("t1-g1"), dest)
        };
        assert_eq!(st, Poll::Failed);
        assert!(!dest.exists());
        // a folder swapped for a junction while the task runs
        let d = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        std::fs::remove_file(part_of(&dest)).unwrap();
        std::fs::remove_dir(d.path().join("Other")).unwrap();
        junction(&d.path().join("Other"), elsewhere.path());
        assert_eq!(g.poll("t1-g1"), Poll::Failed);
        assert_eq!(g.poll("t1-g1"), Poll::Failed);
        let cancels = probe
            .log
            .borrow()
            .iter()
            .filter(|l| l.starts_with("cancel"))
            .count();
        assert_eq!(cancels, 1);
        // the final name taken meanwhile
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        std::fs::write(&dest, b"theirs").unwrap();
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        assert_eq!(g.poll("t1-g1"), Poll::Failed);
        assert_eq!(std::fs::read(&dest).unwrap(), b"theirs");
    }

    #[test]
    fn a_folder_swapped_between_the_last_check_and_the_publish_is_never_reported_as_done() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        let dest = d.path().join("Other").join("a.bin");
        g.submit(&request(&dest)).unwrap();
        *probe.state.borrow_mut() = Some(EngineStatus::Done);
        let (cat, out) = (d.path().join("Other"), elsewhere.path().to_path_buf());
        g.before_publish = Some(Box::new(move || {
            // the swap: the real folder goes, a junction to somewhere else takes its name, and the
            // somewhere else already holds a file called like the part file
            std::fs::remove_dir_all(&cat).unwrap();
            junction(&cat, &out);
            std::fs::write(out.join("a.bin.velqra-part"), b"decoy that is not ours").unwrap();
        }));
        assert_eq!(
            g.status("t1-g1"),
            Ok(EngineStatus::Failed("transfer failed".into()))
        );
        assert_eq!(g.finished("t1-g1"), Some(false));
        assert_eq!(
            std::fs::read(elsewhere.path().join("a.bin.velqra-part")).unwrap(),
            b"decoy that is not ours",
            "a file that is not ours was deleted through the swapped folder"
        );
    }

    #[test]
    fn states_that_do_not_touch_the_file_are_not_checked() {
        let d = tempfile::tempdir().unwrap();
        let probe = Probe::default();
        let mut g = Guarded::new(probe.clone(), d.path().to_path_buf());
        // an unknown attempt (for example after a restart) has no recorded destination: pass through
        *probe.state.borrow_mut() = Some(EngineStatus::Paused);
        assert_eq!(g.status("never-submitted"), Ok(EngineStatus::Paused));
    }
}
