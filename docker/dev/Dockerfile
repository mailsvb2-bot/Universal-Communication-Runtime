FROM rust:1.97.1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --locked --release -p ucr-dev --bin ucr

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates coturn python3 socat \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ucr /usr/local/bin/ucr
COPY crates/ucr-realtime-web/static/client.html /opt/ucr/browser/client.html
COPY docker/dev/index.html /opt/ucr/browser/index.html
COPY docker/dev/webhook_receiver.py /opt/ucr/dev/webhook_receiver.py
COPY docker/dev/turn_credentials.py /opt/ucr/dev/turn_credentials.py
COPY docker/dev/entrypoint.sh /usr/local/bin/ucr-dev-entrypoint

RUN chmod 0755 /usr/local/bin/ucr-dev-entrypoint \
    /opt/ucr/dev/webhook_receiver.py \
    /opt/ucr/dev/turn_credentials.py

EXPOSE 8080 8090 150051 3478/tcp 3478/udp 49160-49170/udp

ENTRYPOINT ["/usr/local/bin/ucr-dev-entrypoint"]
