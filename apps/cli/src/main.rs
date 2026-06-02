use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::Path;
use uuid::Uuid;
use vault_core::Vault;
use vault_types::Record;

#[derive(Parser)]
#[command(name = "vault", about = "Encrypted local vault — store, read, and manage records")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault file
    Create {
        path: String,
        #[arg(long, help = "Password (prompted securely if omitted)")]
        password: Option<String>,
    },
    /// Store a record and print its ID
    Put {
        path: String,
        collection: String,
        kind: String,
        data: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Retrieve a record by ID
    Get {
        path: String,
        id: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Update a record's payload by ID
    Update {
        path: String,
        id: String,
        data: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Delete a record by ID
    Delete {
        path: String,
        id: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// List records, optionally filtered to a collection
    List {
        path: String,
        #[arg(long)]
        collection: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    /// List all collections in the vault
    Collections {
        path: String,
        #[arg(long)]
        password: Option<String>,
    },
}

fn get_password(pw: Option<String>) -> Result<String> {
    match pw {
        Some(p) => Ok(p),
        None => Ok(rpassword::prompt_password("Password: ")?),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { path, password } => {
            let pw = get_password(password)?;
            Vault::create(Path::new(&path), &pw)?;
            println!("Vault created: {}", path);
        }

        Commands::Put { path, collection, kind, data, password } => {
            let pw = get_password(password)?;
            let mut vault = Vault::open(Path::new(&path), &pw)?;
            let record = Record::new(collection, kind, data.into_bytes());
            let id = vault.put(record)?;
            println!("{}", id);
        }

        Commands::Get { path, id, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &pw)?;
            let uuid = id.parse::<Uuid>()?;
            let r = vault.get(&uuid)?;
            println!("id:         {}", r.id);
            println!("collection: {}", r.collection);
            println!("kind:       {}", r.kind);
            println!("created:    {}", r.metadata.created_at);
            println!("updated:    {}", r.metadata.updated_at);
            if !r.metadata.tags.is_empty() {
                println!("tags:       {}", r.metadata.tags.join(", "));
            }
            println!("---");
            println!("{}", String::from_utf8_lossy(&r.payload));
        }

        Commands::Update { path, id, data, password } => {
            let pw = get_password(password)?;
            let mut vault = Vault::open(Path::new(&path), &pw)?;
            let uuid = id.parse::<Uuid>()?;
            vault.update(uuid, data.into_bytes())?;
            println!("Updated {}", id);
        }

        Commands::Delete { path, id, password } => {
            let pw = get_password(password)?;
            let mut vault = Vault::open(Path::new(&path), &pw)?;
            let uuid = id.parse::<Uuid>()?;
            vault.delete(&uuid)?;
            println!("Deleted {}", id);
        }

        Commands::List { path, collection, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &pw)?;
            let mut records = vault.list(collection.as_deref());
            records.sort_by_key(|(_, r)| r.metadata.updated_at);
            if records.is_empty() {
                println!("(no records)");
            } else {
                println!("{:<38} {:<20} {:<10}", "id", "collection", "kind");
                println!("{}", "-".repeat(72));
                for (id, r) in records {
                    println!("{:<38} {:<20} {:<10}", id, r.collection, r.kind);
                }
            }
        }

        Commands::Collections { path, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &pw)?;
            let cols = vault.collections();
            if cols.is_empty() {
                println!("(no collections)");
            } else {
                for col in cols {
                    println!("{}", col);
                }
            }
        }
    }

    Ok(())
}
