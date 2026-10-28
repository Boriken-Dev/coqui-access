//! `unsafe` lives in the files a boundary needs, and only there.

use std::fs;
use std::path::{Path, PathBuf};

/// The files allowed to hold `unsafe`, relative to `src/`. Each must still need it.
const ALLOWED: &[&str] = &["os/windows.rs"];

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("src is readable") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// Whether `text` uses the keyword, outside comments: a block, a function, an impl or an
/// extern block.
fn holds_unsafe(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .any(|line| {
            ["unsafe {", "unsafe fn", "unsafe impl", "unsafe extern"]
                .iter()
                .any(|form| line.contains(form))
        })
}

#[test]
fn unsafe_appears_only_in_the_listed_files_and_each_still_needs_it() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut holding: Vec<String> = files
        .iter()
        .filter(|path| holds_unsafe(&fs::read_to_string(path).expect("a source file")))
        .map(|path| {
            path.strip_prefix(&root)
                .expect("under src")
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
        })
        .collect();
    holding.sort();
    assert_eq!(holding, ALLOWED);
}

#[test]
fn the_scan_sees_each_form_and_ignores_comments() {
    assert!(holds_unsafe("    let x = unsafe { f() };"));
    assert!(holds_unsafe("unsafe fn f() {}"));
    assert!(!holds_unsafe("// SAFETY: unsafe { is fine here"));
    assert!(!holds_unsafe("#![deny(unsafe_code)]"));
}
