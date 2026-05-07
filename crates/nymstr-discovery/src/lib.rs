use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use nym_sdk::mixnet::{Recipient, Socks5MixnetClient};
use nym_validator_client::client::NymApiClient;
use rand::seq::SliceRandom;
use serde::Deserialize;
use tokio::time::sleep;
use url::Url;

pub const DEFAULT_NYM_API: &str = "https://validator.nymtech.net/api/";
const API_TIMEOUT: Duration = Duration::from_secs(20);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize)]
pub struct AddressResponse {
    pub address: String,
}

pub struct Discovery {
    nym_api: Url,
}

impl Default for Discovery {
    fn default() -> Self {
        Self {
            nym_api: Url::parse(DEFAULT_NYM_API).expect("valid default"),
        }
    }
}

impl Discovery {
    pub fn new(nym_api: Url) -> Self {
        Self { nym_api }
    }

    /// Fetch a discovery node's Nym address by tunneling an HTTPS request
    /// to `https://api.<domain>/api/v1/address` through a random exit-policy
    /// network requester on the Nym mixnet.
    pub async fn resolve(&self, domain: &str) -> Result<Recipient> {
        let provider = self.pick_network_requester().await?;
        self.resolve_with(domain, provider).await
    }

    pub async fn resolve_with(&self, domain: &str, provider: Recipient) -> Result<Recipient> {
        tracing::info!(%domain, %provider, "resolving discovery node via mixnet");
        let socks5 = Socks5MixnetClient::connect_new(provider.to_string())
            .await
            .context("connecting socks5 mixnet client")?;

        let socks5_url = socks5.socks5_url();
        tracing::info!(%socks5_url, "issuing HTTPS request via mixnet");
        let result = fetch_address(domain, &socks5_url).await;
        socks5.disconnect().await;

        let resp = result?;
        Recipient::from_str(resp.address.trim())
            .map_err(|e| anyhow!("invalid nym address in response: {e}"))
    }

    async fn pick_network_requester(&self) -> Result<Recipient> {
        let client = NymApiClient::new_with_timeout(self.nym_api.clone(), API_TIMEOUT);
        let nodes = client
            .get_all_described_nodes_v2()
            .await
            .context("fetching described nodes from nym-api")?;

        let candidates: Vec<String> = nodes
            .into_iter()
            .filter_map(|n| n.description.network_requester)
            .filter(|nr| nr.uses_exit_policy)
            .map(|nr| nr.address)
            .collect();

        let pick = candidates
            .choose(&mut rand::thread_rng())
            .ok_or_else(|| anyhow!("no exit-policy network requesters available"))?;

        Recipient::from_str(pick).map_err(|e| anyhow!("invalid NR address {pick}: {e}"))
    }
}

async fn fetch_address(domain: &str, socks5_url: &str) -> Result<AddressResponse> {
    let proxy = reqwest::Proxy::all(socks5_url).context("building socks5 proxy")?;
    let http = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("building reqwest client")?;

    let url = format!("https://api.{domain}/api/v1/address");

    // Socks5MixnetClient::connect_new returns before the SOCKS5 listener has
    // actually bound, so retry the real request with backoff until it accepts.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(100);
    let resp = loop {
        match http.get(&url).send().await {
            Ok(r) => break r,
            Err(e) if is_socks_connect_error(&e) && std::time::Instant::now() < deadline => {
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
            }
            Err(e) => return Err(anyhow::Error::new(e).context(format!("GET {url}"))),
        }
    };

    Ok(resp.error_for_status()?.json::<AddressResponse>().await
        .context("decoding address response")?)
}

fn is_socks_connect_error(err: &reqwest::Error) -> bool {
    if !err.is_connect() {
        return false;
    }
    // Match "failed to create underlying connection" raised by the socks
    // crate when the proxy listener isn't bound yet.
    let mut source: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = source {
        let msg = e.to_string();
        if msg.contains("failed to create underlying connection") {
            return true;
        }
        source = e.source();
    }
    false
}
