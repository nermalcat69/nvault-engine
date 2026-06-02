# nVault

A local-first encrypted storage engine written in Rust. Store arbitrary records — text, JSON, SVG, binary — inside a single encrypted `.vlt` file.

## Crates

| Crate | Role |
|---|---|
| `vault-types` | Shared structs: `Record`, `VaultHeader`, `Metadata` |
| `vault-crypto` | Argon2id key derivation, AES-256-GCM encrypt/decrypt |
| `vault-storage` | Raw `.vlt` file I/O, header parsing |
| `vault-index` | In-memory record index |
| `vault-core` | Public API — orchestrates all layers |
| `apps/cli` | Reference CLI implementation |

## File Format

```
[ Header: 48 bytes, plaintext ]   magic(8) + version(4) + page_size(4) + salt(32)
[ Encrypted payload             ]   nonce(12) + AES-256-GCM ciphertext
```

Everything after the header is encrypted. The payload contains all records and the index, serialized with bincode.

## CLI

```bash
cargo build --bin vault

vault create   <path> [--password <pw>]
vault put      <path> <collection> <kind> <data> [--password <pw>]
vault get      <path> <id> [--password <pw>]
vault update   <path> <id> <data> [--password <pw>]
vault delete   <path> <id> [--password <pw>]
vault list     <path> [--collection <name>] [--password <pw>]
vault collections <path> [--password <pw>]
```

Password is prompted securely if `--password` is omitted.

## Example

```bash
vault create my.vlt
vault put my.vlt notes text "first entry"
# → 3f2e1a...

vault get my.vlt 3f2e1a...
vault list my.vlt --collection notes
vault collections my.vlt
```

## V1 Scope

Create, open, put, get, update, delete, list. Single file. Password protection. No sync, no search, no networking.

## License

See [LICENSE](LICENSE).
