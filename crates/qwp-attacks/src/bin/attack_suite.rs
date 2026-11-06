//! Runs the qWp attack suite.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    reason = "the attack-suite binary reports results to the operator"
)]

use std::process::ExitCode;

use qwp_attacks::run_all;

fn main() -> ExitCode {
    let report = run_all();
    println!(
        "attack-suite: passed={} failed={}",
        report.passed, report.failed
    );
    if report.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
