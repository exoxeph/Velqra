// SPDX-License-Identifier: GPL-3.0-only
//! The Velqra core process. Exit codes: 2 settings unusable, 3 another core is already running,
//! 4 could not start. Messages are fixed text: nothing from outside is ever printed.

use velqra_app::runtime::{Runtime, RuntimeConfig};

fn main() {
    let cfg = match RuntimeConfig::from_env() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("velqra-app: cannot determine settings (set VELQRA_HOME or LOCALAPPDATA)");
            std::process::exit(2);
        }
    };
    let home = cfg.home.clone();
    let _runtime = match Runtime::start(cfg) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("velqra-app: another core is already running");
            std::process::exit(3);
        }
        Err(_) => {
            eprintln!("velqra-app: could not start");
            std::process::exit(4);
        }
    };
    // only after a successful start, so the file always names a live core
    let _ = std::fs::write(home.join("velqra-app.pid"), std::process::id().to_string());
    eprintln!("velqra-app: running");
    loop {
        std::thread::park();
    }
}
