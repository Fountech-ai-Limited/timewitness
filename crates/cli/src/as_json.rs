//! A verifier's result as JSON, for something reading it rather than somebody.
//!
//! This is a view and never a format. Nothing is parsed back from it, nothing is signed over it, and
//! a verifier that read this instead of the receipt bytes would be checking the wrong thing. It
//! exists because a workflow step wants to know whether a receipt held and how wide the bound was,
//! and grep over prose is not an interface.
//!
//! It is built as a value tree and rendered by the receipt crate's own renderer, so the escaping and
//! the byte-to-hexadecimal rule are the same ones a receipt is printed with, in one place.

use timewitness_receipt::{json, Value};
use timewitness_verify::{cannot_prove, Assessment, State};

/// The whole result, rendered.
#[must_use]
pub fn render(a: &Assessment) -> String {
    json::render(&value(a))
}

fn value(a: &Assessment) -> Value {
    let mut top: Vec<(&'static str, Value)> = vec![
        ("accepted", Value::Bool(a.accepted())),
        (
            "steps",
            Value::Array(
                a.steps
                    .iter()
                    .map(|step| {
                        Value::map([
                            ("question", Value::text(step.question.clone())),
                            (
                                "state",
                                Value::text(match step.state {
                                    State::Held(_) => "held",
                                    State::Failed(_) => "failed",
                                    State::NotChecked(_) => "not-checked",
                                }),
                            ),
                            ("detail", Value::text(step.state.detail().to_string())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("receipt_bytes", Value::Int(a.encoded_bytes as i128)),
        ("receipt_sha256", Value::Bytes(a.link.clone())),
        ("anchors_held", Value::Int(a.anchors_held as i128)),
        (
            "cannot_prove",
            Value::Array(
                cannot_prove::limits()
                    .into_iter()
                    .map(|limit| {
                        Value::map([
                            ("section", Value::text(limit.section)),
                            ("limit", Value::text(limit.headline)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];

    if let Some(receipt) = &a.receipt {
        let operators = receipt.claim.operators();
        top.push((
            "claim",
            Value::map([
                // Named so nobody has to be told twice which number is the claim.
                ("kind", Value::text("agent-bound")),
                ("earliest_ns", Value::Int(receipt.claim.earliest.as_nanos())),
                ("latest_ns", Value::Int(receipt.claim.latest.as_nanos())),
                ("width_ns", Value::Int(receipt.width())),
                ("reading_ns", Value::Int(receipt.utc_estimate.as_nanos())),
                ("reading_is_display_only", Value::Bool(true)),
                (
                    "sources_offered",
                    Value::Int(i128::from(receipt.claim.sources_offered)),
                ),
                (
                    "sources_kept",
                    Value::Int(i128::from(receipt.claim.sources_kept)),
                ),
                // The counts a majority actually rests on, and the labels they were counted from,
                // so a caller can do the same arithmetic and get a different answer where ours is
                // wrong.
                ("operators_offered", Value::Int(operators.offered as i128)),
                ("operators_kept", Value::Int(operators.kept as i128)),
                // Neither count above includes a party that is the issuer itself, so a script
                // reading only those two would see a round of three strangers where there were two
                // strangers and one of the issuer's own servers.
                (
                    "operators_first_party",
                    Value::Int(operators.first_party as i128),
                ),
                ("sources", receipt.claim.sources_as_value()),
                ("sequence", Value::Int(i128::from(receipt.sequence))),
            ]),
        ));
    }

    if let Some(evidence) = &a.evidence {
        top.push((
            "evidence",
            Value::Array(
                evidence
                    .entries
                    .iter()
                    .map(|entry| {
                        let (checked, detail) = match &entry.outcome {
                            timewitness_receipt::Outcome::Checked { signer, .. } => {
                                (true, signer.clone())
                            }
                            timewitness_receipt::Outcome::NotChecked(why) => (false, why.clone()),
                        };
                        Value::map([
                            ("role", Value::text(entry.role.as_str())),
                            ("scheme", Value::text(entry.scheme.clone())),
                            ("checked", Value::Bool(checked)),
                            ("against", Value::text(detail)),
                        ])
                    })
                    .collect(),
            ),
        ));
        top.push(("basis_granted", Value::Bool(evidence.basis_granted)));
        top.push(("basis_reason", Value::text(evidence.basis_reason.clone())));
    }

    Value::map(top)
}
