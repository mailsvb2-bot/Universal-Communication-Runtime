# Build endpoint-owned MLS/E2EE WASM from the same revision as the server.
FROM rust:1.97.1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p ucr-dev --bin ucr
RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --version 0.2.128 --locked \
    && cargo build --locked --release \
      --manifest-path crates/ucr-endpoint-wasm/Cargo.toml \
      --target wasm32-unknown-unknown \
    && mkdir -p crates/ucr-realtime-web/static/endpoint-wasm \
    && wasm-bindgen target/wasm32-unknown-unknown/release/ucr_endpoint_wasm.wasm \
      --target web \
      --out-dir crates/ucr-realtime-web/static/endpoint-wasm \
      --out-name ucr_endpoint_wasm \
    && test -s crates/ucr-realtime-web/static/endpoint-wasm/ucr_endpoint_wasm.js \
    && test -s crates/ucr-realtime-web/static/endpoint-wasm/ucr_endpoint_wasm_bg.wasm

# Bundle exactly the existing SDK adapter and its strict canonical authority
# boundary; do not introduce a second crypto implementation or a CDN runtime.
FROM node:22-bookworm-slim AS browser-sdk
WORKDIR /src
COPY sdk/typescript/src ./sdk/typescript/src
RUN mkdir -p /out/endpoint-media \
    && npm exec --yes --package=esbuild@0.25.5 -- \
      esbuild sdk/typescript/src/reference_browser_media_installer.ts \
      --bundle --platform=browser --format=esm --target=es2022 \
      --outfile=/out/endpoint-media/reference_browser_media_installer.js \
    && test -s /out/endpoint-media/reference_browser_media_installer.js

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates coturn python3 socat \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/ucr /usr/local/bin/ucr
COPY crates/ucr-realtime-web/static/client.html /opt/ucr/browser/client.html
COPY --from=builder /src/crates/ucr-realtime-web/static/endpoint-wasm/ /opt/ucr/browser/endpoint-wasm/
COPY --from=browser-sdk /out/endpoint-media/ /opt/ucr/browser/endpoint-media/
COPY docker/dev/index.html /opt/ucr/browser/index.html
COPY docker/dev/webhook_receiver.py /opt/ucr/dev/webhook_receiver.py
COPY docker/dev/turn_credentials.py /opt/ucr/dev/turn_credentials.py
COPY docker/dev/entrypoint.sh /usr/local/bin/ucr-dev-entrypoint
RUN chmod 0755 /usr/local/bin/ucr-dev-entrypoint \
    /opt/ucr/dev/webhook_receiver.py \
    /opt/ucr/dev/turn_credentials.py
EXPOSE 8080 8090 50052 3478/tcp 3478/udp 49160-49170/udp
ENTRYPOINT ["/usr/local/bin/ucr-dev-entrypoint"]
