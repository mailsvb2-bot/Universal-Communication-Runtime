#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use ucr_runtime::{DEFAULT_RUNTIME_BIND, ProductionRuntime};

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
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: ucr-runtime <init|check|metrics|serve> --database PATH [--bind 127.0.0.1:50051]"
        .to_owned()
}
