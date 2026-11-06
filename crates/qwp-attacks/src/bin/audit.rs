//! Audits qWp process artifacts.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the audit binary reports results and errors to the operator"
)]

use std::process::ExitCode;

use qwp_attacks::audit;

fn main() -> ExitCode {
    match audit() {
        Ok(report) => {
            println!("audit: fad_index={}", report.fad_index);
            println!("audit: gap_register={}", report.gap_register);
            println!("audit: traceability={}", report.traceability);
            println!("audit: break_log={}", report.break_log);
            println!("audit: attack_trees={}", report.attack_trees);
            if report.is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("audit: {error}");
            ExitCode::from(2)
        }
    }
}
