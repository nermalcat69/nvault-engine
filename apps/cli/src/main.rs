use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::Path;
use uuid::Uuid;
use vault_core::Vault;
use vault_types::Record;
use zeroize::Zeroizing;

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
    /// Retrieve the latest version of a record
    Get {
        path: String,
        id: String,
        #[arg(long, help = "Retrieve a specific historical version")]
        version: Option<u32>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Update a record's payload (creates a new version)
    Update {
        path: String,
        id: String,
        data: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Delete a record (version history is retained)
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
    /// Show version history for a record
    History {
        path: String,
        id: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Verify vault integrity: chunk hashes, references, and index consistency
    Verify {
        path: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Search records by text content (AND semantics for multiple words)
    Search {
        path: String,
        query: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Close confirmation (vault is always flushed on write; this validates it can be opened)
    Close {
        path: String,
        #[arg(long)]
        password: Option<String>,
    },
}

/// Returns the password wrapped in Zeroizing so the bytes are wiped from
/// memory as soon as the returned value is dropped (after key derivation).
fn get_password(pw: Option<String>) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(match pw {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")?,
    }))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { path, password } => {
            let pw = get_password(password)?;
            Vault::create(Path::new(&path), &*pw)?;
            println!("Vault created: {}", path);
        }

        Commands::Put { path, collection, kind, data, password } => {
            let pw = get_password(password)?;
            let mut vault = Vault::open(Path::new(&path), &*pw)?;
            let record = Record::new(collection, kind, data.into_bytes());
            let id = vault.put(record)?;
            println!("{}", id);
        }

        Commands::Get { path, id, version, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &*pw)?;
            let uuid = id.parse::<Uuid>()?;

            match version {
                Some(v) => {
                    let (rv, payload) = vault.get_version(&uuid, v)?;
                    println!("id:      {}", uuid);
                    println!("version: {} (of {})", rv.version, vault.history(&uuid)?.len());
                    println!("kind:    {}", rv.kind);
                    println!("updated: {}", rv.timestamp);
                    println!("---");
                    println!("{}", String::from_utf8_lossy(&payload));
                }
                None => {
                    let r = vault.get(&uuid)?;
                    let versions = vault.history(&uuid)?.len();
                    println!("id:         {}", r.id);
                    println!("collection: {}", r.collection);
                    println!("kind:       {}", r.kind);
                    println!("version:    {}", versions);
                    println!("created:    {}", r.metadata.created_at);
                    println!("updated:    {}", r.metadata.updated_at);
                    if !r.metadata.tags.is_empty() {
                        println!("tags:       {}", r.metadata.tags.join(", "));
                    }
                    println!("---");
                    println!("{}", String::from_utf8_lossy(&r.payload));
                }
            }
        }

        Commands::Update { path, id, data, password } => {
            let pw = get_password(password)?;
            let mut vault = Vault::open(Path::new(&path), &*pw)?;
            let uuid = id.parse::<Uuid>()?;
            vault.update(uuid, data.into_bytes())?;
            let versions = vault.history(&uuid)?.len();
            println!("Updated {} (now at version {})", id, versions);
        }

        Commands::Delete { path, id, password } => {
            let pw = get_password(password)?;
            let mut vault = Vault::open(Path::new(&path), &*pw)?;
            let uuid = id.parse::<Uuid>()?;
            vault.delete(&uuid)?;
            println!("Deleted {}", id);
        }

        Commands::List { path, collection, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &*pw)?;
            let mut records = vault.list(collection.as_deref());
            records.sort_by_key(|r| r.updated_at);
            if records.is_empty() {
                println!("(no records)");
            } else {
                println!("{:<38} {:<20} {:<10} {}", "id", "collection", "kind", "ver");
                println!("{}", "-".repeat(76));
                for r in records {
                    println!("{:<38} {:<20} {:<10} v{}", r.id, r.collection, r.kind, r.version);
                }
            }
        }

        Commands::Collections { path, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &*pw)?;
            let cols = vault.collections();
            if cols.is_empty() {
                println!("(no collections)");
            } else {
                for col in cols {
                    println!("{}", col);
                }
            }
        }

        Commands::History { path, id, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &*pw)?;
            let uuid = id.parse::<Uuid>()?;
            let history = vault.history(&uuid)?;
            println!("{:<8} {:<12} {}", "version", "timestamp", "kind");
            println!("{}", "-".repeat(40));
            for v in &history {
                println!("v{:<7} {:<12} {}", v.version, v.timestamp, v.kind);
            }
        }

        Commands::Search { path, query, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &*pw)?;
            let results = vault.search(&query);
            if results.is_empty() {
                println!("No results for \"{}\"", query);
            } else {
                println!(
                    "{:<38} {:<20} {:<8} {:<6} {}",
                    "id", "collection", "kind", "score", "matched"
                );
                println!("{}", "-".repeat(84));
                for sr in results {
                    println!(
                        "{:<38} {:<20} {:<8} {:<6.2} {}",
                        sr.record.id,
                        sr.record.collection,
                        sr.record.kind,
                        sr.score,
                        sr.matched_terms.join(", ")
                    );
                }
            }
        }

        Commands::Verify { path, password } => {
            let pw = get_password(password)?;
            let vault = Vault::open(Path::new(&path), &*pw)?;
            let report = vault.verify();

            println!("records checked:   {}", report.records_checked);
            println!("versions checked:  {}", report.versions_checked);
            println!("chunks checked:    {}", report.chunks_checked);
            println!("orphaned chunks:   {}", report.orphaned_chunks);

            if report.ok() {
                println!("\nIntegrity OK — vault is clean.");
            } else {
                println!("\n{} error(s) found:", report.errors.len());
                for e in &report.errors {
                    println!("  • {}", e);
                }
                std::process::exit(1);
            }
        }

        Commands::Close { path, password } => {
            let pw = get_password(password)?;
            Vault::open(Path::new(&path), &*pw)?;
            println!("Vault closed: {}", path);
        }
    }

    Ok(())
}
