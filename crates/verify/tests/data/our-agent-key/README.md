# Two receipts signed by our own key

Both were taken on 2026-09-24 by `timewitness stamp` on the same desktop, over `subject.txt`, with
the agent key our own receipts are signed with. Its public half is
`77a1c78c43c0b1ec55456c54f3abb82473a9f8c98fdaad8886d34cc924238f8a` and its private half is never in
this repository.

`before-its-window.hex` was taken first, before the key log said the key was ours. The entry was
written next, with its window opening at `1790267170000000000` ns, and `inside-its-window.hex` was
taken after that. So the two are signed by one key and told apart by the window alone, which is the
thing they are here to show.

Checked against the key log we serve, the first is refused at `is that key one of ours` and the
refusal names the reading and the window it fell outside; the second is held and the answer names
the entry and its window. `scripts/our-key-in-the-log.sh` puts both through the verifier, with the
committed receipt in `a-real-stamp` beside them, whose key the log does not name, and fails on any
other answer.

The log is our own word about our own keys and it is not third-party evidence. The window is judged
on each receipt's own reading, which whoever holds the key wrote, so it tells these two apart and
would not catch a receipt that lies about when it was signed.
