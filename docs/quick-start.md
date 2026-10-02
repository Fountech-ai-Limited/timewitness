# Quick start: your first verified receipt

Written 2026-09-24. Supersedes nothing.

Before you start, read [what TimeWitness cannot prove](what-timewitness-cannot-prove.md). A receipt
says UTC was somewhere inside an interval and signs that claim. It does not say the time was exact,
and the list says what else it will not tell you.

This page takes you from a machine with nothing of ours on it to a receipt you have checked yourself.
It is written for Ubuntu or Debian. There is no downloadable binary yet, so you compile the command
line from the `v0.5` release, and that is most of the wait. `scripts/walk-the-quick-start.py` runs
every command below, as written here, on a fresh Ubuntu 24.04 container every morning, and goes red
if the last one does not verify.

Stamping asks public time servers, so the machine needs the outbound ports in
[destinations and ports](destinations-and-ports.md). Checking the receipt afterwards asks nothing.

## 1. The tools to compile with

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates build-essential
```

## 2. Rust

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
```

## 3. TimeWitness

```sh
cargo install --locked --git https://github.com/Fountech-ai-Limited/timewitness --tag v0.5 timewitness-cli
```

This puts `timewitness` in `~/.cargo/bin`.

## 4. Stamp a file

```sh
echo "my first stamped file" > hello.txt
timewitness stamp --subject hello.txt --key my-agent.key --out hello.receipt.cbor
```

It polls the time servers over sixteen rounds, which takes anywhere from about ten seconds to about a
minute depending on how quickly they answer, then writes the receipt. `my-agent.key` is made on the
spot because it does not exist yet. It proves that one agent signed the receipt and nothing about
who you are, so keep it if you want your next receipts signed by the same agent.

## 5. Check it

```sh
timewitness verify hello.receipt.cbor --subject hello.txt
```

The first line should read "This receipt holds up as far as it was checked". Below it is every
check that was made, the width of the interval, the evidence for it and whose word each part is,
and the full list of what it cannot prove.

Anybody you hand `hello.txt` and `hello.receipt.cbor` to can run the same check, with no account and
no network. `docs/verifier.md` says what the verifier checks and what it deliberately does not.
