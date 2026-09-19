#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use ucr_runtime::{DEFAULT_RUNTIME_BIND, ProductionRuntime, RealtimeRuntimeConfig};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ucr-runtime: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let mut database = None;
    let mut bind = DEFAULT_RUNTIME_BIND.to_owned();
    let mut join_base_url = None;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--database" => {
                database = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--database requires a path".to_owned())?,
                ));
            }
            "--bind" => {
                bind = args
                    .next()
                    .ok_or_else(|| "--bind requires an address".to_owned())?;
            }
            "--join-base-url" => {
                join_base_url = Some(
                    args.next()
                        .ok_or_else(|| "--join-base-url requires an HTTPS URL".to_owned())?,
                );
            }
            _ => return Err(format!("unknown option: {argument}; {}", usage())),
        }
    }

    let database = database.ok_or_else(|| format!("--database is required; {}", usage()))?;
    match command.as_str() {
        "init" => {
            let diagnostics = ProductionRuntime::initialize_database(&database)?;
            println!("UCR_RUNTIME_INITIALIZED");
            println!("{}", diagnostics.json());
            Ok(())
        }
        "check" => {
            let runtime = ProductionRuntime::open_existing(&database)?;
            println!("UCR_RUNTIME_CHECK_OK");
            println!("{}", runtime.diagnostics()?.json());
            Ok(())
        }
        "metrics" => {
            let runtime = ProductionRuntime::open_existing(&database)?;
            print!("{}", runtime.diagnostics()?.prometheus());
            Ok(())
        }
        "serve" => {
            let bind: SocketAddr = bind
                .parse()
                .map_err(|error| format!("invalid --bind address: {error}"))?;
            Arc::new(ProductionRuntime::open_existing(&database)?)
                .serve(bind)
                .await
        }
        "serve-realtime" => {
            let bind: SocketAddr = bind
                .parse()
                .map_err(|error| format!("invalid --bind address: {error}"))?;
            let join_base_url = join_base_url
                .ok_or_else(|| "--join-base-url is required for serve-realtime".to_owned())?;
            let key_hex = std::env::var("UCR_REALTIME_JOIN_KEY_HEX")
                .map_err(|_| "UCR_REALTIME_JOIN_KEY_HEX is required for serve-realtime".to_owned())?;
            let config = RealtimeRuntimeConfig::new(join_base_url, decode_key_hex(&key_hex)?)?;
            Arc::new(ProductionRuntime::open_existing(&database)?)
                .serve_realtime(bind, config)
                .await
        }
        _ => Err(usage()),
    }
}

fn decode_key_hex(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("UCR_REALTIME_JOIN_KEY_HEX must contain exactly 64 hexadecimal characters".to_owned());
    }
    let mut output = [0_u8; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("UCR_REALTIME_JOIN_KEY_HEX contains a non-hexadecimal character".to_owned()),
    }
}

fn usage() -> String {
    "usage: ucr-runtime <init|check|metrics|serve|serve-realtime> --database PATH [--bind 127.0.0.1:50051] [--join-base-url https://host/conference]"
        .to_owned()
}
