//! `citadel` — a terminal host for the app core.
//!
//! ```text
//! citadel register <handle>          register this device as a new account
//! citadel whoami                     the registered profile
//! citadel lookup <handle>            KT-verify a peer and print their account id
//! citadel dm <handle>... [--title t] open a DM with KT-verified peers
//! citadel send <group-id> <text>     send a message
//! citadel list                       conversations
//! citadel show <group-id>            messages in a conversation
//! citadel sync                       pull everything over REST
//! citadel listen                     hold the gateway open and print what arrives
//! ```
//!
//! Profile root: `$CITADEL_PROFILE` or the platform application-data
//! directory. Services: `CITADEL_AUTH_URL`, `CITADEL_DELIVERY_URL` (compose
//! defaults). Database key and signing seeds: the OS credential store, under
//! `$CITADEL_KEYCHAIN_SERVICE` (default `Citadel`) so a second profile on the
//! same machine gets its own entries.

use anyhow::{bail, Context, Result};
use citadel_app::{AppEvent, CitadelApp, Config};
use citadel_core::store::{CredentialStore, NativeCredentialStore, ProfilePaths};
use citadel_proto::ids::GroupId;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        bail!("usage: see `citadel --help`");
    };
    if command == "--help" || command == "-h" || command == "help" {
        println!("{}", USAGE);
        return Ok(());
    }

    let paths = match std::env::var_os("CITADEL_PROFILE") {
        Some(root) => ProfilePaths::at_root(std::path::PathBuf::from(root)),
        None => ProfilePaths::platform_default().context("platform profile directory")?,
    };
    // One keychain/credential-manager service per profile so several
    // profiles can live on one machine (CITADEL_KEYCHAIN_SERVICE); the
    // default is the one production identity.
    let credentials: Arc<dyn CredentialStore> = match std::env::var("CITADEL_KEYCHAIN_SERVICE") {
        Ok(service) if !service.is_empty() => {
            Arc::new(NativeCredentialStore::with_service(service))
        }
        _ => Arc::new(NativeCredentialStore::new()),
    };
    let app = CitadelApp::open(Config::dev(), paths, credentials).context("open profile")?;

    match command {
        "register" => {
            let handle = args.get(1).context("register <handle>")?;
            let profile = app.register(handle).await?;
            println!(
                "registered {} as account {} device {}",
                profile.handle, profile.account_id, profile.device_id
            );
        }
        "whoami" => match app.profile()? {
            Some(p) => println!(
                "{}\naccount {}\ndevice  {}\nidentity {}",
                p.handle,
                p.account_id,
                p.device_id,
                hex(&p.identity_pubkey)
            ),
            None => println!("no profile registered on this device"),
        },
        "lookup" => {
            let handle = args.get(1).context("lookup <handle>")?;
            app.login().await?;
            let info = app.lookup(handle).await?;
            println!(
                "{} account {} leaf {} identity {} (KT-verified)",
                info.handle,
                info.account_id,
                info.leaf_index,
                hex(&info.identity_pubkey.0)
            );
        }
        "dm" => {
            let mut handles = Vec::new();
            let mut title = None;
            let mut rest = args[1..].iter();
            while let Some(arg) = rest.next() {
                if arg == "--title" {
                    title = rest.next().cloned();
                } else {
                    handles.push(arg.clone());
                }
            }
            if handles.is_empty() {
                bail!("dm <handle>... [--title t]");
            }
            app.login().await?;
            let mut accounts = Vec::new();
            for handle in &handles {
                accounts.push(app.lookup(handle).await?.account_id);
            }
            let group_id = app.create_dm(&accounts, title).await?;
            println!("{group_id}");
        }
        "send" => {
            let group_id: GroupId = parse_group(args.get(1))?;
            let text = args[2..].join(" ");
            if text.is_empty() {
                bail!("send <group-id> <text>");
            }
            app.login().await?;
            app.send(group_id, text.as_bytes()).await?;
            println!("sent");
        }
        "list" => {
            for c in app.conversations()? {
                println!(
                    "{}  epoch {}  {}",
                    c.group_id,
                    c.epoch,
                    c.title.unwrap_or_default()
                );
            }
        }
        "show" => {
            let group_id: GroupId = parse_group(args.get(1))?;
            for m in app.messages(group_id)? {
                println!(
                    "{} {}",
                    if m.outgoing { ">" } else { "<" },
                    String::from_utf8_lossy(&m.plaintext)
                );
            }
        }
        "sync" => {
            app.login().await?;
            app.sync().await?;
            println!("synced");
        }
        "listen" => {
            app.login().await?;
            let mut events = app.events();
            let printer = tokio::spawn(async move {
                while let Ok(event) = events.recv().await {
                    match event {
                        AppEvent::MessageReceived {
                            group_id,
                            plaintext,
                            ..
                        } => println!("[{group_id}] {}", String::from_utf8_lossy(&plaintext)),
                        AppEvent::ConversationJoined(g) => println!("joined {g}"),
                        AppEvent::EpochAdvanced { group_id, epoch } => {
                            println!("[{group_id}] epoch {epoch}")
                        }
                        AppEvent::Warning(text) => eprintln!("warning: {text}"),
                        AppEvent::GatewayConnected => eprintln!("connected"),
                        AppEvent::GatewayDisconnected => eprintln!("disconnected"),
                        _ => {}
                    }
                }
            });
            loop {
                match app.run_gateway().await {
                    Ok(()) => break,
                    Err(error) => {
                        eprintln!("gateway: {error}; reconnecting in 3s");
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                }
            }
            printer.abort();
        }
        other => bail!("unknown command {other}\n{USAGE}"),
    }
    Ok(())
}

const USAGE: &str = "citadel register <handle> | whoami | lookup <handle> | dm <handle>... [--title t] | send <group-id> <text> | list | show <group-id> | sync | listen";

fn parse_group(arg: Option<&String>) -> Result<GroupId> {
    let raw = arg.context("a group id is required")?;
    let uuid = raw.parse().context("group id must be a UUID")?;
    Ok(GroupId::from_uuid(uuid))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
