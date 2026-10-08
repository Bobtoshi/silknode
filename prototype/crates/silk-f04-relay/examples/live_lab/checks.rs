//! Bounded genuine native/restart checks; never payment submission or retry.
use super::{Result, files};
use silk_f04_relay::{
    config::SignedConfig,
    control::Role,
    journal::{Decision, Journal},
    runtime::RoundGuard,
    schedule::Schedule,
};
use std::{
    path::Path,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn config(root: &Path, round: u64) -> Result<SignedConfig> {
    let domain = files::exact::<32>(&root.join("domain"))?;
    let roots = files::exact::<64>(&root.join("roots"))?;
    Ok(SignedConfig::verify(
        files::exact::<770>(&root.join("config"))?.as_ref(),
        *domain,
        0,
        u32::try_from(round / 2880)?,
        [roots[..32].try_into()?, roots[32..].try_into()?],
    )?)
}

pub fn guard(kind: &str, public: &Path, round: u64) -> Result<()> {
    if !matches!(kind, "cpu" | "wall") || !cfg!(target_os = "linux") {
        return Err("expected Linux native cpu or wall probe".into());
    }
    let config = config(public, round)?;
    let schedule = Schedule::functional_fixture(&config, round)?;
    let guard = RoundGuard::arm(&schedule)?;
    assert_eq!(guard.round(), round);
    assert!(RoundGuard::arm(&schedule).is_err());
    let receipt = std::env::var_os("SILK_F04_GUARD_RECEIPT")
        .ok_or("explicit new guard receipt path required")?;
    files::write_new(
        Path::new(&receipt),
        format!(
            "SNF04GUARD1 {kind} {}\n",
            guard.native_wall_deadline()?.as_micros()
        )
        .as_bytes(),
    )?;
    println!(
        "guard_probe={kind} pid={} same_schedule_rearm_refused=true original_wall_remaining_ms={} qualified_utc=false",
        std::process::id(),
        schedule
            .at(30_000_000_000)?
            .saturating_duration_since(Instant::now())
            .as_millis()
    );
    // No further check(), application deadline or shortened production timer.
    // The external supervisor must establish actual SIGKILL, not this print.
    if kind == "cpu" {
        let _worker = thread::spawn(|| {
            let mut state = 1_u64;
            loop {
                state = std::hint::black_box(state.wrapping_mul(3).wrapping_add(1));
            }
        });
        loop {
            thread::park();
        }
    }
    loop {
        thread::sleep(Duration::from_secs(120));
    }
}

pub fn cold_journals(public: &Path, copies: &Path, pins: &Path, old_round: u64) -> Result<()> {
    let config = config(public, old_round)?;
    let utc_round = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    for (name, role, old_decision) in [
        ("a", Role::A, Decision::Open),
        ("b", Role::B, Decision::Abort),
    ] {
        let directory = copies.join(name);
        let before = files::exact::<4096>(&directory.join("CURRENT"))?;
        // This check is specifically for the actual retained failed family,
        // not fabricated coverage of a crash at RELEASE_DECIDED.
        assert_eq!(before[256], old_decision as u8);
        assert_eq!(u64::from_le_bytes(before[264..272].try_into()?), old_round);
        let expected_pin = files::exact::<32>(&pins.join(format!("{name}-pin")))?;
        let mut wrong_pin = *expected_pin;
        wrong_pin[0] ^= 1;
        assert!(Journal::open(&directory, config.domain(), 0, role, wrong_pin, utc_round).is_err());
        assert_eq!(*files::exact::<4096>(&directory.join("CURRENT"))?, *before);
        let mut journal = Journal::open(
            &directory,
            config.domain(),
            0,
            role,
            *expected_pin,
            utc_round,
        )?;
        assert_eq!(journal.decision(old_round), Some(Decision::Abort));
        assert!(journal.earliest_round() > (old_round + 1).max(utc_round + 2));
        let reopened = files::exact::<4096>(&directory.join("CURRENT"))?;
        assert!(journal.abort(old_round).is_err());
        assert!(journal.delivery(old_round, false).is_err());
        let old_body = before[312..440].try_into()?;
        assert!(
            journal
                .begin(&config, old_round, &old_body, utc_round)
                .is_err()
        );
        assert_eq!(
            *files::exact::<4096>(&directory.join("CURRENT"))?,
            *reopened
        );
        // Result receipt only, not independently retained future signing authority.
        files::write_new(&copies.join(format!("{name}-reopened-pin")), &journal.pin())?;
        println!(
            "cold_pid={} role={name} previous={old_decision:?} reopened=Abort old_round_authority=false earliest={} original_evidence_copied=true independent_custody=false",
            std::process::id(),
            journal.earliest_round()
        );
    }
    Ok(())
}
