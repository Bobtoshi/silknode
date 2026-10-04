//! Explicit private file-based operator interface. No listener or wallet secrets.
use rand_core::{OsRng, RngCore};
use silk_f04_node::{
    Digest, Error, Result,
    carriage::{Body, MAX_VERTEX_BYTES},
    genesis::Genesis,
    history::PublicHistoryV1,
    node::{Node, NodeStatus},
    sync::RANGE_LIMIT_V1,
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Arc,
};

const HELP: &str = "silk-f04-local — PRIVATE VALUELESS RESEARCH ONLY
Commands: init | reopen | ingest --vertex PATH | reconcile --max-steps 1..512
          export --index N --out NEW_FILE | mine-empty --reward-owner HEX32
          history-resume --history-root PATH --expected-history-manifest HEX32
          history-ingest --history-root PATH --expected-history-manifest HEX32
            --range PATH --start N --count 1..32 --max-steps 1..512
All commands require:
  --private-valueless --accept-genesis-trust --domain HEX32 --genesis PATH
  --store PATH --host-margin PATH
Except init, additionally require:
  --operator-retained-local --expected-local-head HEX32
  --spend-params PATH --output-params PATH

Expected domain and local head MUST come from independently retained operator
records, never from the supplied bundle or directory. Imported archive vertices
must enter via ingest. Reopen revalidates history and may finish a committed job;
every successful command flushes the clock and prints a NEW local-head pin.
Exception: history-resume reports a receiver-derived request position without
flushing the clock. Both history commands require an independently pinned public
manifest. history-ingest statically binds the whole bounded response before
opening the store, then requires start to equal the receiver-derived prefix.
Every member still uses ordinary native admission/reconciliation. A later native
failure can retain earlier admissions; no atomic batch, automatic retry, saved
cursor adoption or permission to reopen a failed owner is implied.
Retain that pin outside imported inputs. A lost pin/interrupted local job needs
explicit recovery authority; this interface never adopts an unknown head.
Export is one full topologically indexed carrier, NOT canonical wallet order.
No raw-envelope mining/submission, network endpoint, key or wallet interface.
Flags acknowledge scope/trust; they do not establish OS qualification, independent
custody, privacy or acceptance. Use only the separately qualified isolated runtime.";

struct Options {
    command: String,
    fields: BTreeMap<String, String>,
}
impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let command = args.first().ok_or(Error::Invalid("missing CLI command"))?;
        let extra: &[&str] = match command.as_str() {
            "init" | "reopen" => &[],
            "ingest" => &["--vertex"],
            "reconcile" => &["--max-steps"],
            "export" => &["--index", "--out"],
            "mine-empty" => &["--reward-owner"],
            "history-resume" => &["--history-root", "--expected-history-manifest"],
            "history-ingest" => &[
                "--history-root",
                "--expected-history-manifest",
                "--range",
                "--start",
                "--count",
                "--max-steps",
            ],
            _ => return Err(Error::Invalid("unknown CLI command")),
        };
        let mut fields = BTreeMap::new();
        let mut at = 1;
        while at < args.len() {
            let key = &args[at];
            let flag = matches!(
                key.as_str(),
                "--private-valueless" | "--accept-genesis-trust"
            ) || (command != "init" && key == "--operator-retained-local");
            let value_option = ["--domain", "--genesis", "--store", "--host-margin"]
                .contains(&key.as_str())
                || (command != "init"
                    && ["--expected-local-head", "--spend-params", "--output-params"]
                        .contains(&key.as_str()))
                || extra.contains(&key.as_str());
            if !flag && !value_option {
                return Err(Error::Invalid("unknown/inapplicable CLI option"));
            }
            let value = if flag {
                String::new()
            } else {
                at += 1;
                args.get(at)
                    .filter(|v| !v.is_empty() && !v.starts_with("--"))
                    .ok_or(Error::Invalid("missing CLI option value"))?
                    .clone()
            };
            if fields.insert(key.clone(), value).is_some() {
                return Err(Error::Invalid("duplicate CLI option"));
            }
            at += 1;
        }
        let options = Self {
            command: command.clone(),
            fields,
        };
        for required in [
            "--private-valueless",
            "--accept-genesis-trust",
            "--domain",
            "--genesis",
            "--store",
            "--host-margin",
        ] {
            options.get(required)?;
        }
        options.digest("--domain")?;
        if command != "init" {
            for required in [
                "--operator-retained-local",
                "--expected-local-head",
                "--spend-params",
                "--output-params",
            ] {
                options.get(required)?;
            }
            options.digest("--expected-local-head")?;
        }
        for required in extra {
            options.get(required)?;
        }
        if command == "mine-empty" {
            options.digest("--reward-owner")?;
        }
        if command == "export" {
            options.number("--index", 0, 4095)?;
        }
        if matches!(command.as_str(), "history-resume" | "history-ingest") {
            options.digest("--expected-history-manifest")?;
        }
        if command == "history-ingest" {
            options.number("--start", 0, 4095)?;
            options.number("--count", 1, RANGE_LIMIT_V1)?;
        }
        if matches!(command.as_str(), "reconcile" | "history-ingest") {
            options.number("--max-steps", 1, 512)?;
        }
        Ok(options)
    }
    fn get(&self, name: &str) -> Result<&str> {
        self.fields
            .get(name)
            .map(String::as_str)
            .ok_or(Error::Invalid("missing required CLI option"))
    }
    fn digest(&self, name: &str) -> Result<Digest> {
        let text = self.get(name)?;
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid("CLI digest requires exact lowercase hex32"));
        }
        hex::decode(text)
            .map_err(|_| Error::Invalid("CLI digest"))?
            .try_into()
            .map_err(|_| Error::Invalid("CLI digest length"))
    }
    fn number(&self, name: &str, min: usize, max: usize) -> Result<usize> {
        let text = self.get(name)?;
        let n = text
            .parse::<usize>()
            .map_err(|_| Error::Invalid("CLI integer"))?;
        if n < min || n > max || n.to_string() != text {
            return Err(Error::Invalid("CLI integer range/encoding"));
        }
        Ok(n)
    }
}

fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(Error::Invalid("CLI input type/length"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(Error::Invalid("CLI input changed length"));
    }
    Ok(bytes)
}
fn new_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn check_output_path(root: &Path, output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize()?;
    let root = root.canonicalize()?;
    if parent.starts_with(&root) || output.file_name().is_none() {
        return Err(Error::Invalid(
            "public export must be outside the node store namespace",
        ));
    }
    // Both areas must be on the runtime's same accounted/capped filesystem.
    use std::os::unix::fs::MetadataExt;
    if parent.metadata()?.dev() != root.metadata()?.dev() {
        return Err(Error::Invalid(
            "public export must use the same capped task volume",
        ));
    }
    Ok(())
}
fn report(node: &Node) -> Result<()> {
    let status = match node.status()? {
        NodeStatus::Ready => "Ready",
        NodeStatus::NeedsReconcile => "NeedsReconcile",
        NodeStatus::ArchiveReplay => "ArchiveReplay",
    };
    println!(
        "pid={};status={status};domain={};local_head={};vertices={};recovered_previous={};accounted_bytes={}",
        std::process::id(),
        hex::encode(node.genesis().domain()),
        hex::encode(node.local_head()?),
        node.vertex_count(),
        node.recovered_previous(),
        node.accounted_bytes()
    );
    if let Ok(state) = node.state() {
        let (pool, burned) = state.private_counters();
        println!(
            "checkpoint_index={};checkpoint={};state_digest={};leaves={};pool={pool};burned={burned};eligible_cut={}",
            state.checkpoint_index(),
            hex::encode(state.checkpoint_id()),
            hex::encode(state.digest()),
            state.leaves(),
            state.eligible_cut().index
        );
    }
    Ok(())
}
fn run(options: Options) -> Result<()> {
    let genesis = Genesis::admit_local_bundle(
        &bounded_file(Path::new(options.get("--genesis")?), 8 * 1024 * 1024)?,
        &options.digest("--domain")?,
        true,
    )?;
    let root = Path::new(options.get("--store")?);
    let margin = Path::new(options.get("--host-margin")?);
    if options.command == "export" {
        check_output_path(root, Path::new(options.get("--out")?))?;
    }
    if options.command == "init" {
        let mut node = Node::create(root, margin, genesis)?;
        node.flush_clock()?;
        return report(&node);
    }
    // All command syntax and bounded received input are admitted before reopening
    // a store. Supplied public parameters authenticate their whole exact bytes.
    let vertex = if options.command == "ingest" {
        Some(bounded_file(
            Path::new(options.get("--vertex")?),
            MAX_VERTEX_BYTES,
        )?)
    } else {
        None
    };
    let history = if matches!(
        options.command.as_str(),
        "history-resume" | "history-ingest"
    ) {
        Some(PublicHistoryV1::open(
            Path::new(options.get("--history-root")?),
            options.digest("--expected-history-manifest")?,
            Arc::new(genesis.clone()),
        )?)
    } else {
        None
    };
    let response = if options.command == "history-ingest" {
        Some(bounded_file(
            Path::new(options.get("--range")?),
            1 + RANGE_LIMIT_V1 * (4 + MAX_VERTEX_BYTES),
        )?)
    } else {
        None
    };
    // Whole-response static refusal happens before parameter loading or opening
    // any receiver store. This does NOT turn bytes into verified native work.
    let range = response
        .as_deref()
        .map(|bytes| {
            history.as_ref().expect("history input").decode_range(
                bytes,
                options.number("--start", 0, 4095)?,
                options.number("--count", 1, RANGE_LIMIT_V1)?,
            )
        })
        .transpose()?;
    let parameters = SaplingParameters::load(
        Path::new(options.get("--spend-params")?),
        Path::new(options.get("--output-params")?),
    )?;
    let mut node = Node::open_retained_pinned(
        root,
        margin,
        genesis,
        &parameters,
        options.digest("--expected-local-head")?,
    )?;
    if options.command == "history-resume" {
        let history = history.as_ref().expect("history input");
        println!(
            "next_request_start={};source_total={};request_hint_only=true",
            history.admitted_prefix(&node)?,
            history.len()
        );
        return report(&node);
    }
    let outcome = (|| -> Result<()> {
        match options.command.as_str() {
            "reopen" => {}
            "ingest" => {
                println!(
                    "ingress={:?}",
                    node.ingest(vertex.as_deref().expect("ingest input"), &parameters)?
                );
            }
            "history-ingest" => {
                let history = history.as_ref().expect("history input");
                if history.admitted_prefix(&node)? != options.number("--start", 0, 4095)? {
                    return Err(Error::Invalid(
                        "history request is not receiver-derived prefix",
                    ));
                }
                for carrier in range.as_ref().expect("history range").carriers() {
                    println!("ingress={:?}", node.ingest(carrier, &parameters)?);
                    for _ in 0..options.number("--max-steps", 1, 512)? {
                        if node.status()? == NodeStatus::Ready {
                            break;
                        }
                        node.advance()?;
                    }
                    if node.status()? != NodeStatus::Ready {
                        return Err(Error::Paused("history receiver needs reconciliation"));
                    }
                }
                println!(
                    "next_request_start={};source_total={};request_hint_only=true",
                    history.admitted_prefix(&node)?,
                    history.len()
                );
            }
            "reconcile" => {
                for _ in 0..options.number("--max-steps", 1, 512)? {
                    if node.status()? == NodeStatus::Ready {
                        break;
                    }
                    node.advance()?;
                }
            }
            "export" => {
                let records = node.export_range(options.number("--index", 0, 4095)?, 1)?;
                let bytes = records
                    .first()
                    .ok_or(Error::Unavailable("no vertex at export index"))?;
                node.check_public_output_capacity(bytes.len())?;
                if let Err(error) = new_output(Path::new(options.get("--out")?), bytes) {
                    eprintln!(
                        "Export failed; any newly created output is retained and may be incomplete. Never overwrite or import it as accepted data."
                    );
                    return Err(error);
                }
            }
            "mine-empty" => {
                let body = Body::new(&node.genesis().domain(), &[])?;
                let mut nonce = [0; 32];
                OsRng
                    .try_fill_bytes(&mut nonce)
                    .map_err(|_| Error::Unavailable("mining entropy"))?;
                let candidate =
                    node.mine_current(body, options.digest("--reward-owner")?, nonce, None)?;
                println!(
                    "mined_vertex={};timestamp={}",
                    hex::encode(candidate.id),
                    candidate.header.timestamp
                );
                println!(
                    "ingress={:?}",
                    node.ingest(&candidate.encode(), &parameters)?
                );
            }
            _ => unreachable!("validated command"),
        }
        node.flush_clock()?;
        Ok(())
    })();
    // An operation may commit before failing. Report any still-healthy exact
    // head, but never invent one after a fault. A failure remains a nonzero exit.
    if outcome.is_err() {
        let _ = report(&node);
    }
    outcome?;
    report(&node)
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{HELP}");
        return;
    }
    if let Err(error) = Options::parse(&args).and_then(run) {
        eprintln!("{error}\nUse --help. No automatic retry or head adoption.");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "../../tests/common/mod.rs"]
mod common;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    fn init() -> Vec<String> {
        [
            "init",
            "--private-valueless",
            "--accept-genesis-trust",
            "--domain",
            &"12".repeat(32),
            "--genesis",
            "bundle",
            "--store",
            "fresh",
            "--host-margin",
            "margin",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }
    #[test]
    fn options_require_external_acceptance_and_exact_names() {
        assert!(Options::parse(&init()).is_ok());
        let mut a = init();
        a.push("--private-valueless".into());
        assert!(Options::parse(&a).is_err());
        let mut a = init();
        a.remove(2);
        assert!(Options::parse(&a).is_err());
        let mut a = init();
        a[4] = "AB".repeat(32);
        assert!(Options::parse(&a).is_err());
        let mut a = init();
        a[0] = "reopen".into();
        assert!(Options::parse(&a).is_err());
        let mut a = init();
        a.push("--historical".into());
        assert!(Options::parse(&a).is_err());
    }
    fn history_options(command: &str) -> Vec<String> {
        let mut args = init();
        args[0] = command.into();
        args.extend(
            [
                "--operator-retained-local",
                "--expected-local-head",
                &"34".repeat(32),
                "--spend-params",
                "missing-spend",
                "--output-params",
                "missing-output",
                "--history-root",
                "history",
                "--expected-history-manifest",
                &"56".repeat(32),
            ]
            .iter()
            .map(|s| (*s).to_owned()),
        );
        if command == "history-ingest" {
            args.extend(
                [
                    "--range",
                    "response",
                    "--start",
                    "0",
                    "--count",
                    "4",
                    "--max-steps",
                    "386",
                ]
                .iter()
                .map(|s| (*s).to_owned()),
            );
        }
        args
    }
    #[test]
    fn history_commands_require_pins_exact_bounds_and_no_peer_cursor() {
        assert!(Options::parse(&history_options("history-resume")).is_ok());
        assert!(Options::parse(&history_options("history-ingest")).is_ok());
        for (key, value) in [
            ("--start", "4096"),
            ("--start", "00"),
            ("--count", "0"),
            ("--count", "33"),
            ("--max-steps", "0"),
        ] {
            let mut args = history_options("history-ingest");
            let at = args.iter().position(|a| a == key).unwrap();
            args[at + 1] = value.into();
            assert!(Options::parse(&args).is_err());
        }
        let mut args = history_options("history-resume");
        args.extend(["--start".into(), "4".into()]);
        assert!(Options::parse(&args).is_err());
        let mut args = history_options("history-ingest");
        args.extend(["--peer-cursor".into(), "4".into()]);
        assert!(Options::parse(&args).is_err());
    }
    #[test]
    fn history_partial_response_refuses_before_receiver_or_parameter_open() {
        let temp = std::env::var_os("SILK_F04_ANCESTRY_TEST_PARENT").map_or_else(
            || tempfile::tempdir().unwrap(),
            |path| tempfile::tempdir_in(path).unwrap(),
        );
        let genesis = common::fixture(&[10]).genesis;
        let mut manifest = Vec::from(b"SNF04HF1".as_slice());
        manifest.extend_from_slice(&genesis.domain());
        manifest.extend_from_slice(&Sha256::digest(genesis.local_bundle()));
        manifest.extend_from_slice(&[0; 96]);
        manifest.extend_from_slice(&1_u32.to_le_bytes());
        manifest.extend_from_slice(&[0; 4]);
        manifest.extend_from_slice(&[1; 32]);
        manifest.extend_from_slice(&[2; 32]);
        manifest.extend_from_slice(&720_u32.to_be_bytes());
        std::fs::write(temp.path().join("history.manifest"), &manifest).unwrap();
        std::fs::write(temp.path().join("genesis.bundle"), genesis.local_bundle()).unwrap();
        std::fs::write(temp.path().join("response"), [1, 0, 0, 2, 208]).unwrap();
        let mut options = Options::parse(&history_options("history-ingest")).unwrap();
        for (key, value) in [
            ("--domain", hex::encode(genesis.domain())),
            (
                "--expected-history-manifest",
                hex::encode(Sha256::digest(&manifest)),
            ),
            ("--history-root", temp.path().display().to_string()),
            (
                "--genesis",
                temp.path().join("genesis.bundle").display().to_string(),
            ),
            (
                "--range",
                temp.path().join("response").display().to_string(),
            ),
            (
                "--store",
                temp.path().join("never-opened").display().to_string(),
            ),
        ] {
            options.fields.insert(key.into(), value);
        }
        let outcome = run(options);
        assert!(
            matches!(outcome, Err(Error::Invalid("sync range truncated"))),
            "{outcome:?}"
        );
        assert!(!temp.path().join("never-opened").exists());
    }
    #[test]
    fn bounded_input_and_create_new_output_refuse_aliases_or_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public");
        new_output(&path, &[1, 2, 3]).unwrap();
        assert_eq!(bounded_file(&path, 3).unwrap(), [1, 2, 3]);
        assert!(bounded_file(&path, 2).is_err());
        assert!(bounded_file(dir.path(), 3).is_err());
        assert!(new_output(&path, &[4]).is_err());
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(bounded_file(&alias, 3).is_err());
        assert_eq!(std::fs::read(path).unwrap(), [1, 2, 3]);
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        assert!(check_output_path(&store, &store.join("ACTIVE_JOB")).is_err());
        let store_alias = dir.path().join("store-alias");
        std::os::unix::fs::symlink(&store, &store_alias).unwrap();
        assert!(check_output_path(&store, &store_alias.join("output")).is_err());
        assert!(check_output_path(&store, &dir.path().join("export")).is_ok());
    }
}
