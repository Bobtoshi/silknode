//! Explicit one-round, same-host functional fixture; never a deployed relay.
//! Epoch lifecycle, qualified UTC and independent custody are NOT established.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
#[allow(dead_code)]
#[path = "../../../silk-node/tests/support/private_relay_test_certificates.rs"]
mod certificates;
mod checks;
mod files;
mod lifecycle;
mod lifecycle_clients;
mod owners;
mod roles;
mod settlement;
mod setup;

use silk_f04_relay::Error;
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("F04 functional relay fixture STOP: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if std::env::var("SILK_F04_ISOLATED_LAB").as_deref() != Ok("1")
        || args.get(1).map(String::as_str) != Some("--unqualified-functional-lab")
    {
        return Err(
            Error::Unavailable("explicit isolated functional-only admission required").into(),
        );
    }
    match args.get(2).map(String::as_str) {
        Some("settlement") => settlement::run(&args[3..]),
        Some("guard") if args.len() == 6 => {
            checks::guard(&args[3], Path::new(&args[4]), args[5].parse()?)
        }
        Some("cold-journals") if args.len() == 7 => checks::cold_journals(
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
            args[6].parse()?,
        ),
        Some("setup") if args.len() == 5 => {
            setup::prepare(Path::new(&args[3]), Path::new(&args[4]))
        }
        Some("setup-lifecycle") if args.len() == 5 => {
            setup::prepare_lifecycle(Path::new(&args[3]), Path::new(&args[4]))
        }
        Some(role @ ("a" | "b" | "p0" | "p1" | "p2" | "clients")) if args.len() == 4 => {
            roles::run(role, args[3].parse()?, false, false, false)
        }
        Some("owners") if args.len() == 5 => {
            roles::run(&args[3], args[4].parse()?, true, false, false)
        }
        Some("owners-missing-input") if args.len() == 5 => {
            roles::run(&args[3], args[4].parse()?, true, true, false)
        }
        Some("owners-lifecycle") if args.len() == 6 => {
            let offset = args[5].parse()?;
            silk_f04_relay::schedule::initialize_functional_offset(offset)?;
            println!("functional_clock_offset_seconds={offset} qualified_utc=false");
            roles::run(&args[3], args[4].parse()?, true, false, true)
        }
        _ => Err(
            Error::Unavailable("expected setup WALLET_FIXTURE NEW_DIRECTORY or ROLE ROUND").into(),
        ),
    }
}
