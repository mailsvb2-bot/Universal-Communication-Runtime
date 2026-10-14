#![forbid(unsafe_code)]

use std::{net::SocketAddr, sync::Arc};

use ucr_dev::{DEFAULT_DEV_BIND, DEFAULT_ROOM_BIND, DevEnvironment, SandboxScenario};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ucr: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("dev") {
        return Err(
            "usage: ucr dev [--check] [--room] [--bind 127.0.0.1:50051] [--room-bind 127.0.0.1:43123] [--simulate SCENARIO]"
                .to_owned(),
        );
    }
    let mut check = false;
    let mut room = false;
    let mut bind = DEFAULT_DEV_BIND.to_owned();
    let mut room_bind = DEFAULT_ROOM_BIND.to_owned();
    let mut scenario = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--check" => check = true,
            "--room" => room = true,
            "--bind" => {
                bind = args
                    .next()
                    .ok_or_else(|| "--bind requires an address".to_owned())?;
            }
            "--room-bind" => {
                room_bind = args
                    .next()
                    .ok_or_else(|| "--room-bind requires an address".to_owned())?;
            }
            "--simulate" => {
                let name = args
                    .next()
                    .ok_or_else(|| "--simulate requires a scenario".to_owned())?;
                scenario = Some(
                    SandboxScenario::parse(&name)
                        .ok_or_else(|| format!("unknown sandbox scenario: {name}"))?,
                );
            }
            _ => return Err(format!("unknown ucr dev option: {argument}")),
        }
    }

    let bind: SocketAddr = bind
        .parse()
        .map_err(|error| format!("invalid --bind address: {error}"))?;
    if !bind.ip().is_loopback() {
        return Err("ucr dev refuses non-loopback bind addresses".to_owned());
    }
    let room_bind: SocketAddr = room_bind
        .parse()
        .map_err(|error| format!("invalid --room-bind address: {error}"))?;
    if room && !room_bind.ip().is_loopback() {
        return Err("ucr dev room refuses non-loopback bind addresses".to_owned());
    }
    let env = Arc::new(if room {
        DevEnvironment::open_room()?
    } else {
        DevEnvironment::new()?
    });
    if let Some(scenario) = scenario {
        env.simulate(scenario)?;
    }
    if check {
        env.self_check().await?;
        let diagnostics = env.diagnostics()?;
        println!("UCR_DEV_CHECK_OK");
        println!("storage_health={}", diagnostics.storage_health);
        println!("transport_health={}", diagnostics.transport_health);
        println!("sandbox_scenarios={}", SandboxScenario::all().len());
        return Ok(());
    }
    if room {
        env.serve_local_room(bind, room_bind).await
    } else {
        env.serve(bind).await
    }
}
