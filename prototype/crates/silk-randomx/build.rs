//! Verifies and builds the curated vendored `RandomX` v2.0.1 source tree.

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RANDOMX_CURATED_TREE: &str = "bee7375373c0b822a04527e954d948dc5cbb3f23";

fn command_output<I, S>(program: &str, arguments: I, directory: &Path) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .unwrap_or_else(|error| panic!("randomx.build.command:{program}:{error}"));
    assert!(
        output.status.success(),
        "randomx.build.command_failed:{program}:{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    output
}

fn git_value<I, S>(directory: &Path, arguments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = command_output("git", arguments, directory);
    String::from_utf8(output.stdout)
        .expect("randomx.build.git_output_utf8")
        .trim()
        .to_owned()
}

fn verify_source(manifest: &Path, source: &Path) -> (PathBuf, String) {
    assert!(
        source.join("src/randomx.h").is_file() && source.join("CMakeLists.txt").is_file(),
        "randomx.build.vendored_source_missing"
    );
    let root = PathBuf::from(git_value(manifest, ["rev-parse", "--show-toplevel"]))
        .canonicalize()
        .expect("randomx.build.root_canonicalize");
    let source = source
        .canonicalize()
        .expect("randomx.build.source_canonicalize");
    let relative = source
        .strip_prefix(&root)
        .expect("randomx.build.source_outside_repository");
    let index_tree = git_value(&root, ["write-tree"]);
    let relative = relative
        .iter()
        .map(|component| {
            component
                .to_str()
                .filter(|value| {
                    !value.is_empty()
                        && !value
                            .chars()
                            .any(|character| matches!(character, '/' | '\\' | ':'))
                })
                .expect("randomx.build.object_path_utf8")
        })
        .collect::<Vec<_>>()
        .join("/");
    let subtree_spec = format!("{index_tree}:{relative}");
    let source_tree = git_value(&root, ["rev-parse", subtree_spec.as_str()]);
    assert_eq!(
        source_tree, RANDOMX_CURATED_TREE,
        "randomx.build.tree_mismatch"
    );
    (root, source_tree)
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let source = manifest.join("../../vendor/RandomX");
    let (repository, source_tree) = verify_source(&manifest, &source);

    let output_directory = PathBuf::from(env::var_os("OUT_DIR").expect("output directory"));
    let build_directory = output_directory.join("randomx-v2.0.1");
    let archive_directory = build_directory.join("lib");
    if build_directory.exists() {
        std::fs::remove_dir_all(&build_directory).expect("randomx.build.directory_remove");
    }
    std::fs::create_dir_all(&build_directory).expect("randomx.build.output_directory");
    std::fs::create_dir_all(&archive_directory).expect("randomx.build.archive_directory");

    // Build only from the pinned Git tree. This prevents generated MSVC
    // assembly, untracked files, or cloud-backed worktree placeholders from
    // changing or stalling the source actually compiled.
    let build_source = output_directory.join("randomx-source-v2.0.1");
    let source_archive = output_directory.join("randomx-source-v2.0.1.tar");
    if build_source.exists() {
        std::fs::remove_dir_all(&build_source).expect("randomx.build.staged_source_remove");
    }
    std::fs::create_dir_all(&build_source).expect("randomx.build.staged_source_directory");
    command_output(
        "git",
        [
            OsStr::new("archive"),
            OsStr::new("--format=tar"),
            OsStr::new("--output"),
            source_archive.as_os_str(),
            OsStr::new(source_tree.as_str()),
        ],
        &repository,
    );
    command_output(
        "cmake",
        [
            OsStr::new("-E"),
            OsStr::new("tar"),
            OsStr::new("xf"),
            source_archive.as_os_str(),
        ],
        &build_source,
    );
    std::fs::remove_file(&source_archive).expect("randomx.build.staged_source_archive_remove");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target operating system");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target architecture");
    let host = env::var("HOST").expect("build host");
    let target = env::var("TARGET").expect("build target");
    let mut configure = vec![
        OsString::from("-S"),
        build_source.as_os_str().to_owned(),
        OsString::from("-B"),
        build_directory.as_os_str().to_owned(),
        OsString::from("-DARCH=default"),
        OsString::from("-DBUILD_SHARED_LIBS=OFF"),
        OsString::from("-DCMAKE_BUILD_TYPE=Release"),
        OsString::from(format!(
            "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY={}",
            archive_directory.display()
        )),
        OsString::from(format!(
            "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE={}",
            archive_directory.display()
        )),
    ];
    if target_os == "windows" {
        assert_eq!(target_arch, "x86_64", "randomx.build.windows_arch");
        configure.push(OsString::from("-DARCH_ID=x86_64"));
        if target_env == "msvc" {
            configure.push(OsString::from(
                "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
            ));
            let generator = env::var("CMAKE_GENERATOR").ok();
            if generator
                .as_deref()
                .is_none_or(|value| value.contains("Visual Studio"))
            {
                configure.push(OsString::from("-A"));
                configure.push(OsString::from("x64"));
            }
        } else if target_env == "gnu" && host != target {
            configure.push(OsString::from("-DCMAKE_SYSTEM_NAME=Windows"));
            configure.push(OsString::from("-DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc"));
            configure.push(OsString::from(
                "-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++",
            ));
        }
    }

    command_output("cmake", &configure, &manifest);
    command_output(
        "cmake",
        [
            OsStr::new("--build"),
            build_directory.as_os_str(),
            OsStr::new("--config"),
            OsStr::new("Release"),
            OsStr::new("--target"),
            OsStr::new("randomx"),
            OsStr::new("--parallel"),
            OsStr::new("1"),
        ],
        &manifest,
    );

    println!(
        "cargo:rustc-link-search=native={}",
        build_directory.display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        archive_directory.display()
    );
    println!("cargo:rustc-link-lib=static=randomx");
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=dylib=advapi32");
    }
    match (target_os.as_str(), target_env.as_str()) {
        ("macos" | "ios", _) => println!("cargo:rustc-link-lib=c++"),
        ("windows", "msvc") => {}
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }
    println!("cargo:rerun-if-changed=../../vendor/RandomX/src");
    println!("cargo:rerun-if-changed=../../vendor/RandomX/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../../docs/RANDOMX_V2_PROVENANCE.md");
}
