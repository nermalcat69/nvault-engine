# Vault Engine Thesis: Structure, Operation, and V1 Scope

## Abstract

The proposed vault engine is a local-first encrypted storage system written in Rust, designed to store arbitrary user data securely in a single binary container. It is not merely a notes application, and it is not a traditional database server. Instead, it sits in the middle: like an embedded database, but with encryption as its primary design principle. The engine is meant to store text, SVGs, structured records, and arbitrary byte data in a way that is compact, private, portable, and reusable by multiple applications. A notes app would be only one frontend on top of the engine. In the future, other tools such as developer secret managers, knowledge bases, or custom desktop services could also use the same core.

The value of this project lies not only in encryption, but in architecture. The real challenge is to build a storage format that is easy to use from an application, hard to misuse, and safe by default. The engine must provide confidentiality, integrity, and predictable behavior while remaining local-only and lightweight. Its first version should focus on a minimal but solid set of capabilities: create a vault, unlock it, store records, retrieve records, update them, delete them, and list them. Everything else should be treated as later expansion.

## Core Idea

At the highest level, the vault engine is a structured encrypted file. A user creates one vault file, such as `myvault.vlt`, and all records are stored inside it. Each record is a small unit of data with an identifier, a type, and content. The content may be plain text, SVG markup, JSON, code snippets, or raw bytes. The engine does not care what the data means; it only cares how to store, encrypt, and retrieve it safely.

This makes the vault engine fundamentally different from a Markdown-based notes system. Markdown files are human-readable and easy to edit, but they expose data in plaintext. The vault engine instead treats every item as a record inside an encrypted container. This allows the app layer to remain simple while the storage layer handles the hard problems of secrecy and integrity.

## Why Rust

Rust is a strong choice for this engine because the project sits at the boundary of security, storage, and systems programming. A vault engine must be careful with memory, and memory mistakes in security software are especially dangerous. Rust helps prevent use-after-free bugs, buffer overflows, and other memory safety errors before the program even runs. That matters when the engine will handle passwords, encryption keys, and sensitive data.

Rust also makes sense because the engine should be reusable. A core library written in Rust can later power a macOS app, a Windows app, a CLI utility, or even SDKs for other languages. The engine becomes a foundation rather than a one-off application. That is important because the long-term value of the project comes from its ability to be embedded into other products.

## Structure of the Vault

The vault file should follow a layered structure. At the top is a header that identifies the file format, stores a version number, and contains the random salt needed for password-based key derivation. After that comes the encrypted payload, which contains records, indexes, and metadata. Internally, the file can be thought of as a compact binary container made of encrypted pages or chunks.

A simple conceptual layout would look like this:

* Header
* Encrypted metadata
* Encrypted records
* Encrypted index
* Optional version history
* Optional attachments or blobs

The important principle is that almost everything sensitive remains encrypted. The file should not reveal note contents, secret contents, or ideally even much metadata. Even if the vault file is copied, inspected, or uploaded somewhere accidentally, it should look like random bytes without the password.

Each record should contain fields like:

* record ID
* record type
* encrypted payload
* timestamps
* optional tags

This record-based model keeps the system flexible. A text note, an SVG diagram, and a JSON object can all be stored through the same API. The engine does not need separate subsystems for each content type.

## How It Will Work

The lifecycle of the vault begins when the user creates one. The engine generates a salt and derives a master key from the password using a strong password-based key derivation function. That key derivation step is critical because the password itself is usually weak compared to a cryptographic key. The derived key then unlocks the vault structure and protects the data inside.

When the vault is opened, the engine decrypts only what is necessary. Ideally, it should not load everything into memory at once. Instead, records should be accessed on demand. This reduces memory use and makes the app feel responsive even if the vault grows large. When a record is read, the engine decrypts that record, returns it to the application, and then clears any temporary plaintext data as quickly as possible.

When a record is written or updated, the application passes plaintext to the engine. The engine encrypts it, stores the encrypted bytes in the file, and updates the index. When a record is deleted, the engine should remove the reference and overwrite or invalidate the old content in a safe manner where practical. If the engine later supports compaction, it can rewrite the vault to remove stale pages and reduce fragmentation.

A key design principle is that applications should never handle raw encryption details. The notes app or other frontend should only ask the engine for simple actions like create record, update record, or search. The vault engine becomes the trusted boundary where security is enforced.

## Data Model and Extensibility

The first version should use a simple generic record model. That is a deliberate choice because the project is not only for notes. It should be able to hold any data that can be represented as bytes. This means the same vault can store:

* plain text notes
* SVGs and diagrams
* small JSON documents
* snippets of code
* configuration values
* secret strings
* binary attachments

This flexibility is what makes the engine valuable as infrastructure rather than just a notes app. The application layer can decide how to present the data, but the engine remains content-agnostic.

In later versions, the model can expand to support folders, collections, tags, references, and version history. However, those features should not complicate the first release. V1 should prove that the core storage and encryption model is correct before any richer organization layer is added.

## V1 Scope

The first version should be intentionally small. Its purpose is to prove the architecture, not to become a full product immediately. V1 should include only the essentials:

1. Create a new vault file.
2. Unlock an existing vault with a password.
3. Store a record.
4. Read a record.
5. Update a record.
6. Delete a record.
7. List records.
8. Close the vault safely.

That is enough to validate the engine. A CLI should be built alongside it because a command-line interface is the fastest way to test behavior, inspect errors, and verify file operations without needing a UI. A CLI also makes the engine easier to integrate into other tools later.

V1 should also define the file format clearly and version it properly. If the format changes later, old vaults must still be readable or at least migratable. That means the header should include a format version and the engine should be strict about compatibility.

## What V1 Should Not Include

A good thesis must also define boundaries. V1 should not try to do everything. It should not include sync, cloud backup, multi-device collaboration, team features, shared vaults, real-time editing, full-text search, or custom cryptography research. Those are all interesting later, but they create complexity that can hide fundamental bugs.

V1 should also avoid pretending to be a database server. It should not become PostgreSQL. It should remain a local embedded engine with one primary job: store encrypted records securely inside a single file. That keeps the scope realistic and the architecture clean.

## Conclusion

The vault engine is best understood as an encrypted embedded storage system, not a notes app and not a server database. Its purpose is to store arbitrary data locally in a single binary file while keeping that data private and structured. Rust is a strong implementation choice because the engine must be safe, fast, and reusable. The internal design should be record-based, encrypted by default, and accessible through a small clean API.

The first version should be deliberately modest: create, unlock, write, read, update, delete, and list. If that core works well, the engine can later become the foundation for many different applications. A notes app, secret manager, knowledge base, or developer data store could all sit on top of the same core. That is what makes the project powerful. The value is not just in encryption, but in building a durable storage foundation that other software can trust and reuse.
