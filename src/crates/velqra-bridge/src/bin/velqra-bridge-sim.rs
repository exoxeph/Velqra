// SPDX-License-Identifier: GPL-3.0-only
use std::collections::BTreeMap;
use velqra_bridge::sim::{exhaustive, exhaustive_pairs, run_plan, seeded, Summary};

fn arg(args: &[String], name: &str, default: u64) -> u64 {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn report(name: &str, s: &Summary) -> i32 {
    println!(
        "{name}: fault points: {}  runs: {}  not completed: {}  violations: {}",
        s.points,
        s.runs,
        s.not_completed,
        s.violations.len()
    );
    for v in s.violations.iter().take(10) {
        println!("VIOLATION {v}");
    }
    i32::from(!s.violations.is_empty())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("exhaustive") => report("single-fault", &exhaustive()),
        Some("pairs") => report("pairwise", &exhaustive_pairs()),
        Some("seeded") => {
            let seeds = arg(&args, "--seeds", 1000);
            let faults = arg(&args, "--faults", 3) as usize;
            let horizon = run_plan(vec![], true).points.len() * 2;
            let (mut bad, mut gave_up) = (0u64, 0u64);
            let mut injected: BTreeMap<usize, u64> = BTreeMap::new();
            for seed in 0..seeds {
                let r = seeded(seed, faults, horizon);
                *injected.entry(r.injected.len()).or_default() += 1;
                gave_up += u64::from(r.gave_up);
                if !r.violations.is_empty() {
                    bad += 1;
                    if bad <= 3 {
                        println!("seed {seed}: {:?} injected={:?}", r.violations, r.injected);
                    }
                }
            }
            println!("seeds: {seeds}  planned faults/run: {faults}  violations: {bad}  client gave up: {gave_up}");
            println!("actually injected per run (a planned fault can miss its point):");
            for (n, c) in &injected {
                println!(
                    "  {n} injected: {c} runs ({:.1}%)",
                    *c as f64 * 100.0 / seeds as f64
                );
            }
            i32::from(bad != 0)
        }
        _ => {
            eprintln!("usage: velqra-bridge-sim exhaustive | pairs | seeded --seeds N --faults K");
            2
        }
    };
    std::process::exit(code);
}
