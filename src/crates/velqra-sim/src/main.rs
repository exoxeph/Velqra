// SPDX-License-Identifier: GPL-3.0-only
use velqra_sim::invariants::{check, classify};
use velqra_sim::scenarios::{baseline, exhaustive, exhaustive_pairs, seeded, Summary};

fn arg(args: &[String], name: &str, default: u64) -> u64 {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn report(name: &str, s: &Summary) -> i32 {
    println!(
        "{name}: fault points: {}  runs: {}  violations: {}",
        s.points,
        s.runs,
        s.violations.len()
    );
    let mut outcomes: Vec<_> = s.outcomes.iter().collect();
    outcomes.sort_by_key(|(o, _)| format!("{o:?}"));
    for (o, n) in outcomes {
        println!("  {o:?}: {n}");
    }
    for v in s.violations.iter().take(10) {
        println!("VIOLATION {v}");
    }
    if s.violations.is_empty() {
        0
    } else {
        1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("exhaustive") => report("single-fault", &exhaustive()),
        Some("pairs") => report("pairwise", &exhaustive_pairs()),
        Some("seeded") => {
            let seeds = arg(&args, "--seeds", 1000);
            let faults = arg(&args, "--faults", 3) as usize;
            let (_, points) = baseline();
            let horizon = points.len() * 2;
            let mut bad = 0u64;
            let mut hist = std::collections::BTreeMap::new();
            let mut injected_hist = std::collections::BTreeMap::new();
            for seed in 0..seeds {
                let r = seeded(seed, faults, horizon);
                *hist.entry(format!("{:?}", classify(&r))).or_insert(0u64) += 1;
                *injected_hist.entry(r.injected.len()).or_insert(0u64) += 1;
                let v = check(&r);
                if !v.is_empty() {
                    bad += 1;
                    if bad <= 3 {
                        println!("seed {seed}: {v:?} injected={:?}", r.injected);
                    }
                }
            }
            println!("seeds: {seeds}  planned faults/run: {faults}  violations: {bad}");
            println!("actually injected per run (a planned fault can miss its point):");
            for (n, c) in &injected_hist {
                println!(
                    "  {n} injected: {c} runs ({:.1}%)",
                    *c as f64 * 100.0 / seeds as f64
                );
            }
            for (o, n) in &hist {
                println!("  {o}: {n}");
            }
            i32::from(bad != 0)
        }
        _ => {
            eprintln!("usage: velqra-sim exhaustive | pairs | seeded --seeds N --faults K");
            2
        }
    };
    std::process::exit(code);
}
