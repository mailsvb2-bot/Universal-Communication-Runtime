#![forbid(unsafe_code)]

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use ucr_core::WebhookDispatchOutcome;
use ucr_runtime::{
    DEFAULT_RUNTIME_BIND, DEFAULT_WEBHOOK_WORKER_POLL_INTERVAL, MachineAuthRuntimeConfig,
    ProductionRuntime, RealtimeRuntimeConfig,
};
use zeroize::Zeroizing;

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
    let mut tenant_id = None;
    let mut namespace_id = None;
    let mut subscription_id = None;

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
            "--tenant-id" => {
                tenant_id = Some(
                    args.next()
                        .ok_or_else(|| "--tenant-id requires an opaque identifier".to_owned())?,
                );
            }
            "--namespace-id" => {
                namespace_id =
                    Some(args.next().ok_or_else(|| {
                        "--namespace-id requires an opaque identifier".to_owned()
                    })?);
            }
            "--subscription-id" => {
                subscription_id =
                    Some(args.next().ok_or_else(|| {
                        "--subscription-id requires an opaque identifier".to_owned()
                    })?);
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
        "serve-realtime" => serve_realtime_command(&database, &bind, join_base_url).await,
        "serve-auth" => serve_auth_command(&database, &bind).await,
        "dispatch-webhook-once" => dispatch_webhook_once(
            &database,
            tenant_id,
            namespace_id.as_deref(),
            subscription_id,
        ),
        "run-webhook-worker" => run_webhook_worker(&database).await,
        _ => Err(usage()),
    }
}

async fn serve_auth_command(database: &PathBuf, bind: &str) -> Result<(), String> {
    let bind: SocketAddr = bind
        .parse()
        .map_err(|error| format!("invalid --bind address: {error}"))?;
    let issuer = required_env("UCR_MACHINE_TOKEN_ISSUER")?;
    let audience = required_env("UCR_MACHINE_TOKEN_AUDIENCE")?;
    let signing_key_id = required_env("UCR_MACHINE_TOKEN_SIGNING_KEY_ID")?;
    let token_endpoint = required_env("UCR_MACHINE_TOKEN_ENDPOINT")?;
    let jwks_uri = required_env("UCR_MACHINE_TOKEN_JWKS_URI")?;
    let signing_key_file = required_env("UCR_MACHINE_TOKEN_SIGNING_KEY_FILE")?;
    let max_ttl_seconds = std::env::var("UCR_MACHINE_TOKEN_MAX_TTL_SECONDS")
        .ok()
        .map(|value| {
            value.parse::<u32>().map_err(|_| {
                "UCR_MACHINE_TOKEN_MAX_TTL_SECONDS must be an unsigned integer".to_owned()
            })
        })
        .transpose()?
        .unwrap_or(900);
    let signing_seed = read_machine_token_signing_key(&signing_key_file)?;
    let config = MachineAuthRuntimeConfig::new(
        issuer,
        audience,
        signing_key_id,
        signing_seed,
        token_endpoint,
        jwks_uri,
        max_ttl_seconds,
    )?;
    Arc::new(ProductionRuntime::open_existing(database)?)
        .serve_machine_auth(bind, config)
        .await
}

fn required_env(variable: &str) -> Result<String, String> {
    std::env::var(variable).map_err(|_| format!("{variable} is required for serve-auth"))
}

fn read_machine_token_signing_key(path: &str) -> Result<[u8; 32], String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect machine token signing key file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("machine token signing key path must be a regular non-symlink file".to_owned());
    }
    if metadata.len() > 256 {
        return Err("machine token signing key file exceeds the bounded size".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "machine token signing key file must not be readable or writable by group/others"
                    .to_owned(),
            );
        }
    }

    let mut bytes = Zeroizing::new(
        fs::read(path).map_err(|error| format!("read machine token signing key file: {error}"))?,
    );
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes.pop();
    }
    let encoded = std::str::from_utf8(bytes.as_slice())
        .map_err(|_| "machine token signing key file must contain ASCII hex".to_owned())?;
    decode_key_hex_named(encoded, "machine token signing key file")
}

async fn serve_realtime_command(
    database: &PathBuf,
    bind: &str,
    join_base_url: Option<String>,
) -> Result<(), String> {
    let bind: SocketAddr = bind
        .parse()
        .map_err(|error| format!("invalid --bind address: {error}"))?;
    let join_base_url =
        join_base_url.ok_or_else(|| "--join-base-url is required for serve-realtime".to_owned())?;
    let key_hex = std::env::var("UCR_REALTIME_JOIN_KEY_HEX")
        .map_err(|_| "UCR_REALTIME_JOIN_KEY_HEX is required for serve-realtime".to_owned())?;
    let turn_rest_secret = std::env::var("UCR_WEBRTC_TURN_SECRET_HEX")
        .ok()
        .map(|value| decode_key_hex_named(&value, "UCR_WEBRTC_TURN_SECRET_HEX"))
        .transpose()?;
    let turn_ttl_seconds = std::env::var("UCR_WEBRTC_TURN_TTL_SECONDS")
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "UCR_WEBRTC_TURN_TTL_SECONDS must be an unsigned integer".to_owned())
        })
        .transpose()?
        .unwrap_or(300);
    let config = RealtimeRuntimeConfig::new(join_base_url, decode_key_hex(&key_hex)?)?
        .with_webrtc_ice(
            csv_env("UCR_WEBRTC_STUN_URLS"),
            csv_env("UCR_WEBRTC_TURN_URLS"),
            turn_rest_secret,
            turn_ttl_seconds,
            bool_env("UCR_WEBRTC_RELAY_ONLY")?.unwrap_or(false),
        )?
        .with_browser_realtime_gateway(
            bool_env("UCR_BROWSER_REALTIME_GATEWAY_ENABLED")?.unwrap_or(false),
        );
    Arc::new(ProductionRuntime::open_existing(database)?)
        .serve_realtime(bind, config)
        .await
}

fn dispatch_webhook_once(
    database: &PathBuf,
    tenant_id: Option<String>,
    namespace_id: Option<&str>,
    subscription_id: Option<String>,
) -> Result<(), String> {
    let tenant_id =
        tenant_id.ok_or_else(|| "--tenant-id is required for dispatch-webhook-once".to_owned())?;
    let subscription_id = subscription_id
        .ok_or_else(|| "--subscription-id is required for dispatch-webhook-once".to_owned())?;
    let key_hex = std::env::var("UCR_WEBHOOK_SIGNING_KEY_HEX").map_err(|_| {
        "UCR_WEBHOOK_SIGNING_KEY_HEX is required for dispatch-webhook-once".to_owned()
    })?;
    let runtime = ProductionRuntime::open_existing(database)?;
    let outcome = runtime.dispatch_webhook_once(
        &tenant_id,
        namespace_id,
        &subscription_id,
        decode_key_hex_named(&key_hex, "UCR_WEBHOOK_SIGNING_KEY_HEX")?,
    )?;
    match outcome {
        WebhookDispatchOutcome::Idle => println!("UCR_WEBHOOK_DISPATCH outcome=idle"),
        WebhookDispatchOutcome::RetryAfter { retry_after_ms } => {
            println!("UCR_WEBHOOK_DISPATCH outcome=retry_after retry_after_ms={retry_after_ms}");
        }
        WebhookDispatchOutcome::Delivered => {
            println!("UCR_WEBHOOK_DISPATCH outcome=delivered");
        }
        WebhookDispatchOutcome::RetryScheduled => {
            println!("UCR_WEBHOOK_DISPATCH outcome=retry_scheduled");
        }
        WebhookDispatchOutcome::DeadLettered => {
            println!("UCR_WEBHOOK_DISPATCH outcome=dead_lettered");
        }
    }
    Ok(())
}

async fn run_webhook_worker(database: &PathBuf) -> Result<(), String> {
    let key_hex = std::env::var("UCR_WEBHOOK_SIGNING_KEY_HEX")
        .map_err(|_| "UCR_WEBHOOK_SIGNING_KEY_HEX is required for run-webhook-worker".to_owned())?;
    let poll_interval = std::env::var("UCR_WEBHOOK_POLL_INTERVAL_MS")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|_| "UCR_WEBHOOK_POLL_INTERVAL_MS must be an unsigned integer".to_owned())
        })
        .transpose()?
        .unwrap_or(DEFAULT_WEBHOOK_WORKER_POLL_INTERVAL);
    Arc::new(ProductionRuntime::open_existing(database)?)
        .run_webhook_worker(
            decode_key_hex_named(&key_hex, "UCR_WEBHOOK_SIGNING_KEY_HEX")?,
            poll_interval,
        )
        .await
}

fn csv_env(variable: &str) -> Vec<String> {
    std::env::var(variable)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn bool_env(variable: &str) -> Result<Option<bool>, String> {
    let Ok(value) = std::env::var(variable) else {
        return Ok(None);
    };
    match value.as_str() {
        "1" | "true" | "TRUE" => Ok(Some(true)),
        "0" | "false" | "FALSE" => Ok(Some(false)),
        _ => Err(format!("{variable} must be true/false or 1/0")),
    }
}

fn decode_key_hex(value: &str) -> Result<[u8; 32], String> {
    decode_key_hex_named(value, "UCR_REALTIME_JOIN_KEY_HEX")
}

fn decode_key_hex_named(value: &str, variable: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "{variable} must contain exactly 64 hexadecimal characters"
        ));
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
        _ => Err("key contains a non-hexadecimal character".to_owned()),
    }
}

fn usage() -> String {
    "usage: ucr-runtime <init|check|metrics|serve|serve-auth|serve-realtime|dispatch-webhook-once|run-webhook-worker> --database PATH [--bind 127.0.0.1:50051] [--join-base-url https://host/conference] [--tenant-id ID] [--namespace-id ID] [--subscription-id ID]"
        .to_owned()
}
