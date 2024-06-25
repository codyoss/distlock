use super::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::HeaderMap;
use reqwest::Client;
use rsa::pkcs8::DecodePrivateKey;
use rustls::sign::Signer;
use rustls_pemfile::Item;
use serde::{Deserialize, Serialize};
use tokio::time::{self, Duration};

const GCE_METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";
const GCE_METADATA_HOST_DNS: &str = "metadata.google.internal";
const DEFAULT_GCE_METADATA_HOST: &str = "169.254.169.254";

fn _new_metadata_client() -> Client {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert("Metadata-Flavor", "Google".parse().unwrap());
    Client::builder().default_headers(headers).build().unwrap()
}

async fn is_running_on_gce() -> bool {
    if std::env::var(GCE_METADATA_HOST_ENV).is_ok() {
        return true;
    }
    let client = _new_metadata_client();
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

    let client = _new_metadata_client();
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

    let token_response: ComputeToken = serde_json::from_str(resp.as_str()).map_err(Error::wrap)?;
    if token_response.expires_in == 0 || token_response.access_token.is_empty() {
        return Err(Error::new("incomplete token received from metadata"));
    }
    Ok(token_response)
}

#[derive(Clone, Deserialize)]
struct ServiceAccountKeyFile {
    #[serde(rename = "type")]
    cred_type: String,
    client_email: String,
    private_key_id: String,
    private_key: String,
    auth_uri: String,
    token_uri: String,
    project_id: String,
}

/// The response of a Service Account Key token exchange.
#[derive(Deserialize)]
struct ServiceAccountToken {
    access_token: String,
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    expires_in: i64,
}

#[derive(Serialize)]
pub struct JwsClaims<'a> {
    pub iss: &'a str,
    pub scope: &'a str,
    pub aud: &'a str,
    pub exp: i64,
    pub iat: i64,
    pub sub: &'a str,
}

impl JwsClaims<'_> {
    pub fn encode(&mut self) -> Result<String> {
        let json = serde_json::to_string(&self).map_err(Error::wrap)?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }
}

#[derive(Serialize)]
pub struct JwsHeader<'a> {
    pub alg: &'a str,
    pub typ: &'a str,
    pub kid: &'a str,
}

impl ServiceAccountKeyFile {
    fn new() -> Result<Self> {
        let key_file = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").map_err(|_| {
            Error::new("please set GOOGLE_APPLICATION_CREDENTIALS to service account")
        })?;
        let key_file = std::fs::read_to_string(key_file).map_err(Error::wrap)?;
        let key_file: ServiceAccountKeyFile =
            serde_json::from_str(key_file.as_str()).map_err(Error::wrap)?;
        Ok(key_file)
    }

    async fn fetch_service_account_token() -> Result<ServiceAccountToken> {
        let client = Client::new();
        let key_file = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").map_err(|_| {
            Error::new("please set GOOGLE_APPLICATION_CREDENTIALS to service account")
        })?;
        let key_file = std::fs::read_to_string(key_file).map_err(Error::wrap)?;
        let key_file: ServiceAccountKeyFile =
            serde_json::from_str(key_file.as_str()).map_err(Error::wrap)?;

        Err(Error::new("something"))
    }

    fn signer(&self) -> Result<String> {
        let key =
            rsa::RsaPrivateKey::from_pkcs8_pem(&self.private_key).map_err(|e| Error::wrap(e))?;

        let now = chrono::Utc::now();
        let mut claims = JwsClaims {
            iss: &self.client_email,
            sub:  &self.client_email,
            scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/devstorage.full_control",
            aud: &self.token_uri,
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
        };
        let header = JwsHeader {
            alg: "RS256",
            typ: "JWT",
            kid: &self.private_key_id,
        };

        // encode all the things
        let json = serde_json::to_string(&claims).map_err(Error::wrap)?;
        let encoded_claims = URL_SAFE_NO_PAD.encode(json);
        let json = serde_json::to_string(&header).map_err(Error::wrap)?;
        let encoded_header = URL_SAFE_NO_PAD.encode(json);

        let ss = format!("{}.{}", encoded_header, encoded_claims);
        let sig = key
            .sign(
                rsa::pkcs1v15::Pkcs1v15Sign::new(),
                ss.as_bytes(),
            )
            .map_err(|_| Error::new("unable to sign bytes"))?;
        Ok(format!("{}.{}", ss, URL_SAFE_NO_PAD.encode(sig)))
    }
}
