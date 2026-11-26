# syntax=docker/dockerfile:1

FROM rust:1.100-bookworm AS builder
WORKDIR /src

# Build release binary.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked -p rship-cli \
    && strip /src/target/release/rship

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/rship /usr/local/bin/rship

ENV RSHIP_CONFIG=/config/config.toml
ENV RSHIP_STATE_DIR=/state

ENTRYPOINT ["/usr/local/bin/rship"]
CMD ["--help"]
