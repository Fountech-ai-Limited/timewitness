//! The list of what this product cannot prove, carried inside the verifier.
//!
//! Every public claim ships beside what it cannot prove, and the list is a section rather than a
//! disclaimer at the bottom. A verifier reporting on a receipt is the sharpest place that rule
//! applies: it is the moment a stranger is told that something about time has been established, and
//! it is the moment they are most likely to believe more than was established.
//!
//! So the list is in the output, not in a document the output points at. It is compiled in from
//! `docs/what-timewitness-cannot-prove.md`, which is the one copy of it in the tree, so the verifier
//! cannot fall behind the document. The headline of each item is what appears beside a result; the
//! whole file is available too, for a reader who wants the reasoning rather than the summary.

/// The list itself, as it sits in the repository.
///
/// Compiled in rather than read at run time, because a verifier that has to find a file beside
/// itself is a verifier that can be run without one.
pub const DOCUMENT: &str = include_str!("../../../docs/what-timewitness-cannot-prove.md");

/// One thing the product cannot prove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    /// Which part of the list it sits under.
    pub section: String,
    /// The item itself, in the words the document uses.
    pub headline: String,
}

/// Every item on the list, in the order the document carries them.
///
/// An item is a paragraph opening with a bold sentence, which is how the document is written. The
/// parse is deliberately literal: a document that stops being written that way produces an empty
/// list, and the test below fails rather than the verifier quietly printing nothing.
///
/// **A headline that wraps is one headline, and reading it as none was a defect found on
/// 2026-09-09.** The document wraps at a hundred columns and several of its items open with a
/// sentence longer than that, so the closing `**` sits on the next line. This function looked for
/// both markers on one line, found one, and dropped the item without a sound. Six items were
/// missing from `timewitness cannot-prove` and from the verifier's own output when it was found,
/// and the failure is the worst shape there is for a list of what cannot be proved: the list still
/// printed, still looked whole, and the items it lost were the ones with the most to say, because a
/// long lead is a long lead for a reason. So a lead is now joined across lines until its closing
/// marker, and the test below pins the count against the document rather than against a number
/// somebody typed.
#[must_use]
pub fn limits() -> Vec<Limit> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut lead: Option<String> = None;
    for line in DOCUMENT.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim().to_string();
            lead = None;
            continue;
        }

        // A blank line ends a paragraph, so a lead still open at one was never a lead. Dropping it
        // here keeps a stray pair of asterisks from swallowing the rest of the document.
        if line.trim().is_empty() {
            lead = None;
            continue;
        }

        let carrying = match lead.take() {
            Some(mut open) => {
                open.push(' ');
                open.push_str(line);
                open
            }
            None => match line.strip_prefix("**") {
                Some(rest) => rest.to_string(),
                None => continue,
            },
        };

        match carrying.find("**") {
            Some(end) => out.push(Limit {
                section: section.clone(),
                headline: carrying[..end].trim().to_string(),
            }),
            None => lead = Some(carrying),
        }
    }
    out
}

/// The list as lines a person reads, grouped under the sections the document uses.
#[must_use]
pub fn lines() -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for limit in limits() {
        if limit.section != current {
            current.clone_from(&limit.section);
            out.push(String::new());
            out.push(format!("  {current}"));
        }
        out.push(format!("    {}", limit.headline));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_the_verifier_prints_is_the_list_in_the_repository() {
        let all = limits();
        // The document carried twenty-two items when this was written. The check is that the parse
        // still finds a list rather than that it finds a fixed number, because the list grows, and a
        // test asserting the count would be edited every time it did until somebody edited it to
        // zero.
        assert!(
            all.len() >= 20,
            "the cannot-prove list parsed to {} items, so either the document changed shape or the \
             verifier is about to print nothing",
            all.len()
        );
        assert!(all.iter().all(|l| !l.headline.is_empty()));
        assert!(all.iter().all(|l| !l.section.is_empty()));
    }

    /// Every bold lead in the document reaches the list, however it wraps.
    ///
    /// The count is taken from the document rather than typed here, so this cannot rot into a
    /// number somebody lowered. What it catches is the failure it was written for: a parse that
    /// reads only the leads short enough to fit on one line still returns a plausible list, and the
    /// test above passes on it, because twenty items is still twenty items.
    #[test]
    fn an_item_whose_lead_wraps_across_lines_is_still_an_item() {
        let opens = DOCUMENT
            .lines()
            .filter(|line| line.starts_with("**"))
            .count();
        assert_eq!(
            limits().len(),
            opens,
            "the document opens {opens} paragraphs with a bold lead and the parse found {}",
            limits().len()
        );

        let wrapped = DOCUMENT
            .lines()
            .filter(|line| line.starts_with("**") && !line[2..].contains("**"))
            .count();
        assert!(
            wrapped > 0,
            "no lead in the document wraps any more, so this test is watching nothing"
        );

        // And the joined headline is one sentence rather than a line with a newline in it.
        assert!(limits().iter().all(|l| !l.headline.contains('\n')));
    }

    #[test]
    fn the_two_items_a_receipt_reader_most_needs_are_on_it() {
        let all = limits();
        assert!(
            all.iter()
                .any(|l| l.headline.contains("cannot prove exact UTC")),
            "the bound is milliseconds and the list has to say so"
        );
        assert!(
            all.iter().any(|l| l.headline.contains("does not prevent")),
            "a receipt records and never stops anything, and the list has to say so"
        );
    }
}
