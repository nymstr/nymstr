# Discovery address publisher (reference implementation)

A nymstr desktop client bootstraps by tunneling an HTTPS request through the
Nym mixnet to:

```
https://api.<domain>/api/v1/address
```

…and expects a JSON response of the form:

```json
{ "address": "<id>.<key>@<gateway>" }
```

This directory contains a minimal Cloudflare Worker that satisfies that
contract, plus a script to update the published address. It is **one
possible implementation** — anything that serves the URL and JSON shape
above will work. Use it as a template for your own discovery node, or
replace it with a static file, an S3 bucket + CloudFront, a `caddy`
config, etc.

## What's here

| File                    | Purpose                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `worker.js`             | Cloudflare Worker: reads `address` from KV and serves it       |
| `set-address.sh`        | Pushes a Nym address into the KV namespace via the Cloudflare API |
| `wrangler.toml.example` | Wrangler config template (copy to `wrangler.toml`)             |

The contract the worker implements:

- `GET /api/v1/address` → `200 { "address": "..." }` if set, `503` if not
- Anything else → `404`

## Deploying the Worker

1. Add your domain to a Cloudflare account.
2. Install + auth wrangler: `npm i -g wrangler && wrangler login`.
3. Copy the config template and fill in your details:
   ```sh
   cp wrangler.toml.example wrangler.toml
   # edit: set zone_name + route to your domain, leave kv_namespaces id blank for now
   ```
4. Create the KV namespace and copy its `id` into `wrangler.toml`:
   ```sh
   wrangler kv namespace create DISCOVERY_KV
   ```
5. Deploy:
   ```sh
   wrangler deploy
   ```

The route declared in `wrangler.toml` (`api.<your-domain>/api/v1/*`) attaches
automatically as long as the zone is on the same Cloudflare account.

## Publishing addresses with `set-address.sh`

Create an API token at <https://dash.cloudflare.com/profile/api-tokens>
("Create Token" → "Custom token") with **Account → Workers KV Storage → Edit**
scoped to your account. Then export:

```sh
export CF_API_TOKEN="..."          # the token above
export CF_ACCOUNT_ID="..."         # dashboard right sidebar
export CF_KV_NAMESPACE_ID="..."    # from `wrangler kv namespace create`
export DISCOVERY_DOMAIN="..."      # optional; enables a post-publish verify
```

Usage:

```sh
# publish a known address
./set-address.sh "Ab1...cd.Ef2...gh@Ij3...kl"

# pull it from a running nymstr-server's log
./set-address.sh --from-server-log /var/log/nymstr-server.log

# show what's currently in KV
./set-address.sh --show
```

The script only talks to the account-scoped KV API — no zone access needed.

## Pointing clients at your discovery node

The desktop client defaults to resolving via `nymstr.com`. To use your own:

- **Per-user**: enter the discovery node's Nym address directly in
  **Settings → Server address**. Manual entries are preserved across
  auto-resolves.
- **Fork the client**: change the bootstrap domain in
  `app/desktop/src/commands/connection.rs` (`ensure_server_address`) from
  `"nymstr.com"` to your domain so first-launch auto-resolution targets it.

## Rotation behavior

Clients cache the resolved address in their local `settings.json`. After
publishing a new address:

- Cold-start clients pick it up on next launch (subject to the worker's
  `cache-control: max-age=300`).
- Warm clients keep using the cached address until they fail to connect
  and call `resolve_server_address` with `force: true`.

If you need a hard cutover, run both old and new discovery nodes in
parallel until clients drain.
