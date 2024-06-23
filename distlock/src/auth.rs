use super::{Error, Result};
use http::HeaderMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::{self, Duration};

const GCE_METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";
const GCE_METADATA_HOST_DNS: &str = "metadata.google.internal";
const DEFAULT_GCE_METADATA_HOST: &str = "169.254.169.254";

fn new_metadata_client() -> Client {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert("Metadata-Flavor", "Google".parse().unwrap());
    Client::builder().default_headers(headers).build().unwrap()
}

async fn is_running_on_gce() -> bool {
    if std::env::var(GCE_METADATA_HOST_ENV).is_ok() {
        return true;
    }
    let client = new_metadata_client();
    let res1 = client.get("http://169.254.169.254").send();
    let res2 = tokio::net::TcpListener::bind((GCE_METADATA_HOST_DNS, 0));

    // Race pinging the metadata service by IP and DNS. Depending on the
    // environment different requests return faster. In the future we should
    // check for more env vars.
    let check = tokio::select! {
        _ = time::sleep(Duration::from_secs(5)) => false,
        _ = res1 => true,
        _ = res2 => true,
    };
    if check {
        return true;
    }

    false
}

#[derive(Deserialize)]
struct ComputeToken {
    pub access_token: String,
    pub expires_in: i64,
}

async fn fetch_compute_access_token() -> Result<ComputeToken> {
    let suffix = format!("instance/service-accounts/default/token");
    let query = &[("scopes", "https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/devstorage.full_control")];
    let host = std::env::var(GCE_METADATA_HOST_ENV)
        .unwrap_or_else(|_| -> String { String::from(DEFAULT_GCE_METADATA_HOST) });
    let suffix = suffix.trim_start_matches('/');

    let client = new_metadata_client();
    let resp = backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
        let url = format!("http://{}/computeMetadata/v1/{}", host, suffix);
        let req = client.get(url).query(query);
        let res = req.send().await.map_err(Error::wrap)?;
        if !res.status().is_success() {
            return Err(backoff::Error::transient(Error::new(format!(
                "bad request with status: {}",
                res.status().as_str()
            ))));
        }
        let content = res.text().await.map_err(Error::wrap)?;
        Ok(content)
    })
    .await?;

    let token_response: ComputeToken =
        serde_json::from_str(resp.as_str()).map_err(Error::wrap)?;
    if token_response.expires_in == 0 || token_response.access_token.is_empty() {
        return Err(Error::new("incomplete token received from metadata"));
    }
    Ok(token_response)
}
