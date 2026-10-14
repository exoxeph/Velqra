// SPDX-License-Identifier: GPL-3.0-only
//! The native-messaging host that Chrome starts. See `host_main` for behaviour and exit codes.

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(velqra_app::host_main::run(args));
}

#[cfg(not(windows))]
fn main() {
    eprintln!("velqra-host: only implemented on Windows");
    std::process::exit(1);
}
