//! A sentence the product prints carries no run of spaces in the middle of it.
//!
//! A long message is written across several source lines with a backslash at the end of each, so
//! the next line's indent is dropped. Lose the backslash, or join the lines by hand, and the indent
//! lands inside the sentence: "so it is the socket              rather than the datagrams". Worse,
//! a lost backslash after `\n` puts a line break and seventeen spaces into a one-line refusal, and a
//! reader that writes refusals into a report one to a line gets a line of our own it never wrote.
//! Fourteen of them were found at once on 2026-09-21, in refusals a person reads, so this reads the
//! source for the shape rather than trusting each message to be looked at.
//!
//! The rule: inside a string literal that does not open with a space, no word is followed by four
//! or more spaces and then a lower-case letter or a placeholder, and no `\n` is followed by four or
//! more spaces and a lower-case letter. A literal that opens with a space is a column of the help
//! text or a labelled line of a report, where lining things up is the point, and it is left alone.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The string literals on one line of source, as the text between the quotes.
///
/// Good enough for this tree: it follows escapes, skips a quote written as a character literal,
/// and does not try to read raw strings, which carry no messages here.
fn literals(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
            break;
        }
        if chars[i] == '\'' && chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'\'') {
            i += 3;
            continue;
        }
        if chars[i] == '"' {
            let mut text = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    text.push(chars[i]);
                    text.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                text.push(chars[i]);
                i += 1;
            }
            out.push(text);
        }
        i += 1;
    }
    out
}

/// Whether a literal carries the shape, and the rule it breaks if so.
fn fault(text: &str) -> Option<&'static str> {
    if text.starts_with(' ') {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    for start in 0..chars.len() {
        let after_word = start > 0 && !chars[start - 1].is_whitespace() && chars[start] == ' ';
        let after_break = start >= 2
            && chars[start - 2] == '\\'
            && chars[start - 1] == 'n'
            && chars[start] == ' ';
        if !(after_word || after_break) {
            continue;
        }
        let run = chars[start..].iter().take_while(|c| **c == ' ').count();
        let next = chars.get(start + run).copied();
        let lower = next.is_some_and(|c| c.is_ascii_lowercase() || c == '{');
        if run >= 4 && lower {
            return Some(if after_break {
                "a line break and an indent inside one message"
            } else {
                "a run of spaces inside a sentence"
            });
        }
    }
    None
}

#[test]
fn no_message_in_the_source_carries_a_lost_line_join() {
    let root = workspace();
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("crates"))
        .expect("the crates")
        .flatten()
    {
        rust_files(&entry.path().join("src"), &mut files);
    }
    files.sort();
    assert!(files.len() > 50, "the walk found {} files", files.len());

    let mut found = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("a source file reads");
        for (n, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for literal in literals(line) {
                if let Some(why) = fault(&literal) {
                    found.push(format!(
                        "{}:{}: {why}",
                        file.strip_prefix(&root).unwrap_or(file).display(),
                        n + 1
                    ));
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn the_rule_refuses_both_shapes_and_leaves_a_lined_up_column_alone() {
    assert!(fault("so it is the socket              rather than the datagrams").is_some());
    assert!(fault("polls                  answered so far").is_some());
    assert!(fault("altered after it \\n                 was signed").is_some());
    assert!(fault("the point is {} and a mean would be {mean}, so it is not     {x}").is_some());
    assert!(fault("  signed by      {}").is_none());
    assert!(fault("      --fields            the pair as lines").is_none());
    assert!(fault("one sentence, with single spaces only").is_none());
    assert!(fault("a table cell   42").is_none());
    assert_eq!(
        literals(r#"write!(f, "one {x}", '"', "two  three") // "not this""#),
        vec!["one {x}".to_string(), "two  three".to_string()]
    );
}
