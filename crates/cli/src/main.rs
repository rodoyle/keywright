//! keywright CLI entrypoint: install, enroll, and (later milestones)
//! approve/import. Privileged operations require a human at the keyboard.

use clap::{Parser, Subcommand, ValueEnum};
use keywright_cli::{CliError, DataDir, install, recover_server_cert};
use keywright_core::role::Role;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "keywright", about = "Credential lifecycle broker CLI")]
struct Cli {
    /// Broker data dir override (defaults to the platform service location).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Generate all material but skip OS-level registration (for tests/dev).
    #[arg(long)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum RoleArg {
    Agent,
    Admin,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Agent => Role::Agent,
            RoleArg::Admin => Role::Admin,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Install the broker: data dir, transport CA, service units.
    Install,
    /// Issue a client certificate (human-controlled enrollment).
    Enroll {
        /// Stable identity name (becomes the cert CN).
        #[arg(long)]
        name: String,
        /// Client role: agent (MCP adapter) or admin (human CLI).
        #[arg(long, value_enum)]
        role: RoleArg,
        /// Where to write client.pem / client.key.
        #[arg(long)]
        out: PathBuf,
    },
    /// Reissue the broker server certificate (transport recovery).
    RecoverTransport,
    /// Approve a pending operation (admin identity required).
    Approve {
        /// The operation id returned by the broker.
        op: String,
        /// Directory holding the enrolled admin client.pem/client.key.
        #[arg(long, default_value = "./keywright-admin")]
        client_dir: PathBuf,
    },
    /// Import a secret value for a credential (read from stdin — never
    /// argv) and deliver it to the broker over mTLS.
    Import {
        /// Credential id to import material for.
        #[arg(long)]
        id: String,
        /// Directory holding the enrolled admin client.pem/client.key.
        #[arg(long, default_value = "./keywright-admin")]
        client_dir: PathBuf,
    },
    /// List broker-managed credentials (metadata only).
    List {
        /// Directory holding an enrolled client.pem/client.key.
        #[arg(long, default_value = "./keywright-admin")]
        client_dir: PathBuf,
    },
}

fn default_data_dir() -> PathBuf {
    keywright_core::datadir::default_data_dir()
}

fn main() {
    let cli = Cli::parse();
    let dd = DataDir::new(cli.data_dir.unwrap_or_else(default_data_dir));
    let result = match cli.command {
        Command::Install => install(&dd, cli.dry_run).map(|i| {
            println!(
                "installed at {}\nage recipient: {}\nBACK UP the age identity ({}); \
                 without it encrypted material is unrecoverable.",
                i.data_dir.display(),
                i.recipient,
                dd.age_identity().display()
            );
            if i.dry_run {
                println!("(dry-run: no OS service registration or ACL changes applied)");
            }
        }),
        Command::Enroll { name, role, out } => keywright_cli::enroll(&dd, &name, role.into(), &out)
            .map(|issued| {
                println!(
                    "enrolled {} as {} (role); wrote {} and {}",
                    name,
                    issued.role,
                    out.join("client.pem").display(),
                    out.join("client.key").display()
                );
            }),
        Command::RecoverTransport => recover_server_cert(&dd).map(|c| {
            println!(
                "reissued broker server certificate (not after {}); restart the broker",
                openssl_cert_not_after(&c.cert_pem)
            );
        }),
        Command::Approve { op, client_dir } => with_broker_client(&dd, &client_dir, |client| {
            keywright_cli::client::approve(client, &op)
        })
        .map_err(CliError::from),
        Command::Import { id, client_dir } => {
            println!("Paste the secret value, then press Enter (input is hidden from argv):");
            with_broker_client(&dd, &client_dir, |client| {
                keywright_cli::client::import_from_stdin(client, &id)
            })
            .map_err(CliError::from)
        }
        Command::List { client_dir } => {
            with_broker_client(&dd, &client_dir, keywright_cli::client::list)
                .map_err(CliError::from)
        }
    };
    if let Err(e) = result {
        eprintln!("keywright: {e}");
        std::process::exit(1);
    }
}

fn openssl_cert_not_after(cert_pem: &str) -> String {
    match keywright_core::trust::parse_cert(cert_pem) {
        Ok(cert) => cert.not_after().to_string(),
        Err(_) => "<unknown>".to_string(),
    }
}

/// Build a broker client from the installed layout and run one operation.
fn with_broker_client(
    dd: &keywright_cli::DataDir,
    client_dir: &std::path::Path,
    op: impl FnOnce(
        &keywright_cli::client::BrokerClient,
    ) -> Result<String, keywright_cli::client::ClientError>,
) -> Result<(), keywright_cli::client::ClientError> {
    let addr = keywright_cli::client::BrokerClient::addr_from_config(dd)?;
    let client = keywright_cli::client::BrokerClient::from_dirs(dd, client_dir, addr)?;
    let response = op(&client)?;
    println!("{response}");
    Ok(())
}
