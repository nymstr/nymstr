# Discovery address publisher

Publishes the nymstr discovery-server Nym address at
`https://api.nymstr.com/api/v1/address` via a Cloudflare Worker backed by KV.

## One-time setup

1. Add `nymstr.com` to your Cloudflare account (free plan is fine). Update
   registrar nameservers to Cloudflare's.

2. Install wrangler and log in:
   ```sh
   npm i -g wrangler
   wrangler login
   ```

3. Create the KV namespace and copy the `id` into `wrangler.toml`:
   ```sh
   cd scripts/discovery
   wrangler kv namespace create DISCOVERY_KV
   # -> binding = "DISCOVERY_KV", id = "abc123..."
   ```

4. Deploy the worker:
   ```sh
   wrangler deploy
   ```
   Wrangler will attach the `api.nymstr.com/api/v1/*` route automatically.

## Credentials for the update script

Create an API token at <https://dash.cloudflare.com/profile/api-tokens>
("Create Token" → "Custom token") with:

- **Account** → **Workers KV Storage** → **Edit**
- Account Resources: your account
- TTL: set as you prefer (rotating tokens yearly is reasonable)

Export three env vars (put them in `~/.zshrc` or a local `.envrc`):

```sh
export CF_API_TOKEN="..."            # the token above
export CF_ACCOUNT_ID="..."           # dashboard right sidebar
export CF_KV_NAMESPACE_ID="..."      # from `wrangler kv namespace create`
```

The Zone ID is only needed by wrangler at deploy time (it reads it from
`wrangler.toml`'s `zone_name`). The update script only talks to the
account-scoped KV API, so it doesn't need zone access.

## Usage

```sh
# Publish an address
./set-address.sh "Ab1...cd.Ef2...gh@Ij3...kl"

# Pull it from a running nymstr-server's log
./set-address.sh --from-server-log /var/log/nymstr-server.log

# Check what's currently published
./set-address.sh --show
```

Clients cache the resolved address locally (`settings.json`), so rotations
take effect on next cold resolve or when clients hit a connection failure
and call `resolve_server_address` with `force: true`.
