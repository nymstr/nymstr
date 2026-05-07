# Nymstr

Privacy-first messenger built on the [Nym mixnet](https://nymtech.net/). Anonymous transport,
PGP identity, MLS group encryption, sealed-sender P2P. Cargo workspace; Tauri desktop client.

## Repo layout

| Path                       | What it is                                                      |
| -------------------------- | --------------------------------------------------------------- |
| `app/`                     | Tauri desktop client (React + TS frontend, Rust backend)        |
| `nymstr-server/`           | Discovery node + P2P relay                                      |
| `nymstr-group/`            | Group server (MLS commits, fan-out)                             |
| `crates/nymstr-common`     | Shared types & protocol structs                                 |
| `crates/nymstr-crypto`     | PGP + MLS crypto primitives                                     |
| `crates/nymstr-transport`  | Nym mixnet transport abstraction (+ stdio for tests)            |
| `crates/nymstr-discovery`  | Resolves discovery address via `api.<domain>` over mixnet SOCKS5|
| `scripts/discovery/`       | Cloudflare Worker that publishes the discovery address          |

## Prerequisites

- [Rust](https://rustup.rs/) 1.86+
- [Node.js](https://nodejs.org/) 18+ and [pnpm](https://pnpm.io/)
- Platform deps for Tauri 2 — see [tauri.app/start/prerequisites](https://tauri.app/start/prerequisites/)

## Run the desktop app

```sh
cd app
pnpm install
pnpm tauri dev
```

On first launch the client auto-resolves the discovery-server Nym address by tunneling
an HTTPS request to `https://api.nymstr.com/api/v1/address` through the mixnet, then
caches it in `settings.json`. To point at a different discovery node, set the address
manually in **Settings → Server address** (manual entries are preserved across resolves).

Build a release binary:

```sh
cd app
pnpm tauri build
```

## Run a discovery server

For local dev or self-hosting:

```sh
cd nymstr-server
cp .env.example .env
cargo run --release -- --generate   # one-time: generate server PGP keys
cargo run --release                  # prints the Nym address; back up the seed phrase
```

Copy the printed Nym address into the desktop client (**Settings → Server address**)
or publish it to your own `api.<domain>/api/v1/address` endpoint — see
[`scripts/discovery/README.md`](scripts/discovery/README.md) for the Cloudflare Worker
setup that backs `api.nymstr.com`.

Full server docs: [`nymstr-server/README.md`](nymstr-server/README.md).

## Run a group server

```sh
cd nymstr-group
cargo run --release
```

Group servers register themselves with a discovery node; see
[`nymstr-group/README.md`](nymstr-group/README.md).

## Tests

```sh
cargo test --workspace          # unit + integration
cargo test -p nymstr-tests-e2e  # end-to-end with real PGP/MLS crypto
```

## Protocol

Wire format and authentication flows are documented in [`PROTOCOL.md`](PROTOCOL.md).
Frontend ↔ backend command surface lives in [`app/WIRING_SPEC.md`](app/WIRING_SPEC.md).

## License

GPL-3.0
