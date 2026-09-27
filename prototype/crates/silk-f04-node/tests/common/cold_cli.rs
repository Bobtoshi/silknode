//! Actual exec'd node lifetimes; not wallet/relay isolation or seed recovery.
use silk_f04_node::genesis::Genesis;
use std::{path::Path, process::Command};

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .flat_map(|line| line.split(';'))
        .find_map(|item| {
            let (key, value) = item.split_once('=')?;
            (key == name).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing {name}: {text}"))
}
pub fn verify(
    lab: &Path,
    margin: &Path,
    parameters: &Path,
    genesis: &Genesis,
    initial_head: &str,
    checkpoint: &str,
    state: &str,
    first_bytes: &[u8],
) {
    let bundle = lab.join("public-genesis.bundle");
    std::fs::write(&bundle, genesis.local_bundle()).unwrap();
    let invoke = |command: &str, store: &Path, pin: Option<&str>, extra: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_silk-f04-local"));
        c.arg(command)
            .args([
                "--private-valueless",
                "--accept-genesis-trust",
                "--domain",
                &hex::encode(genesis.domain()),
                "--genesis",
            ])
            .arg(&bundle)
            .arg("--store")
            .arg(store)
            .arg("--host-margin")
            .arg(margin);
        if let Some(pin) = pin {
            c.args([
                "--operator-retained-local",
                "--expected-local-head",
                pin,
                "--spend-params",
            ])
            .arg(parameters.join("sapling-spend.params"))
            .arg("--output-params")
            .arg(parameters.join("sapling-output.params"));
        }
        let output = c.args(extra).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "{command}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!(
            "cold_cli={command};pid={};vertices={}",
            field(&stdout, "pid"),
            field(&stdout, "vertices")
        );
        stdout
    };
    let store = lab.join("node-a");
    let a = invoke("reopen", &store, Some(initial_head), &[]);
    assert_eq!(field(&a, "checkpoint"), checkpoint);
    assert_eq!(field(&a, "state_digest"), state);
    assert_eq!(field(&a, "vertices"), "16");
    assert_eq!(field(&a, "recovered_previous"), "false");
    assert_eq!(field(&a, "status"), "Ready");
    let b = invoke("reopen", &store, Some(field(&a, "local_head")), &[]);
    assert_ne!(field(&a, "pid"), field(&b, "pid"));
    assert_eq!(field(&b, "checkpoint"), checkpoint);
    assert_eq!(field(&b, "state_digest"), state);
    let exported = lab.join("first-export.vertex");
    let _ = invoke(
        "export",
        &store,
        Some(field(&b, "local_head")),
        &["--index", "0", "--out", exported.to_str().unwrap()],
    );
    assert_eq!(std::fs::read(exported).unwrap(), first_bytes);
    let fresh = lab.join("node-cold-current-time");
    let created = invoke("init", &fresh, None, &[]);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mined = invoke(
        "mine-empty",
        &fresh,
        Some(field(&created, "local_head")),
        &["--reward-owner", &"00".repeat(32)],
    );
    assert_eq!(field(&mined, "vertices"), "1");
    let timestamp = field(&mined, "timestamp").parse::<u64>().unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((before..=after + 15).contains(&timestamp));
    let reopened = invoke("reopen", &fresh, Some(field(&mined, "local_head")), &[]);
    assert_eq!(field(&reopened, "vertices"), "1");
    assert_eq!(field(&reopened, "status"), "Ready");
    assert_eq!(field(&reopened, "recovered_previous"), "false");
    assert!(!fresh.join("ACTIVE_JOB").exists());
    println!("cold_node_processes=6; genuine_current_wall_mining=true; wallet_recovery=false");
}
