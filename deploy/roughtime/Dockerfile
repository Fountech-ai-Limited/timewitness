# A Roughtime server of ours, built from this tree and run as the shipped binary.
#
# The binary is `timewitness roughtime-serve`, the same one a person installs, rather than a
# server-shaped thing built only for the host. That is deliberate: a deployment running different
# code from the one we ship is a deployment whose behaviour nothing in the repository describes.
#
# Nothing here carries a key. The long-term key arrives as TIMEWITNESS_ROUGHTIME_KEY from the
# platform's secret store, because these hosts have no persistent disk and a key generated at
# startup is an identity nobody published.

# The 1.x line rather than a pinned patch, which is what CI installs as well. The workspace states
# 1.80 as the floor and the lockfile is taken as it stands, so what moves between builds is the
# compiler rather than any dependency.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p timewitness-cli

# Debian rather than a scratch image. The server makes outbound TLS calls of its own, to the NTS
# sources that discipline its clock, so it needs the certificate store; an image with no roots is
# an image where a third of the sources fail and the bound quietly rests on the rest.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/timewitness /usr/local/bin/timewitness

# Not root. It binds a port over 1024 and reads a key out of the environment, so it needs nothing
# a normal account does not have.
RUN useradd --system --create-home --shell /usr/sbin/nologin roughtime
USER roughtime

# The address is the platform's own, and it is not a style choice: UDP on this host reaches a
# process only where the process is bound to that name. Binding 0.0.0.0 here answers nobody.
ENTRYPOINT ["/usr/local/bin/timewitness", "roughtime-serve", "--bind", "fly-global-services:2002"]
