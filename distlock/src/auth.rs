#![allow(unused)]

use super::{Error, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::HeaderMap;
use reqwest::Client;

use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey};

use serde::{Deserialize, Serialize};
use tokio::time::{self, Duration};

const GCE_METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";
const GCE_METADATA_HOST_DNS: &str = "metadata.google.internal";
const DEFAULT_GCE_METADATA_HOST: &str = "169.254.169.254";

#[derive(Deserialize)]
pub(crate) struct Token {
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Serialize)]
struct JwsClaims<'a> {
    pub iss: &'a str,
    pub scope: &'a str,
    pub aud: &'a str,
    pub exp: i64,
    pub iat: i64,
    pub sub: &'a str,
}

#[derive(Serialize)]
struct JwsHeader<'a> {
    pub alg: &'a str,
    pub typ: &'a str,
    pub kid: &'a str,
}

#[async_trait]
pub(crate) trait TokenProvider: Send {
    async fn fetch_token(&self) -> Result<Token>;
}

pub(crate) fn new_token_provider() -> Result<Box<dyn TokenProvider>> {
    let sa = ServiceAccountKeyFile::new()?;
    Ok(Box::new(sa))
}

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

async fn fetch_compute_access_token() -> Result<Token> {
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

    let token_response: Token = serde_json::from_str(resp.as_str()).map_err(Error::wrap)?;
    if token_response.expires_in == 0 || token_response.access_token.is_empty() {
        return Err(Error::new("incomplete token received from metadata"));
    }
    Ok(token_response)
}

#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    assertion: String,
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

impl ServiceAccountKeyFile {
    fn new() -> Result<Self> {
        let key_file = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").map_err(|_| {
            Error::new("please set GOOGLE_APPLICATION_CREDENTIALS to service account file")
        })?;
        let key_file = std::fs::read_to_string(key_file).map_err(Error::wrap)?;
        let key_file: ServiceAccountKeyFile =
            serde_json::from_str(key_file.as_str()).map_err(Error::wrap)?;
        Ok(key_file)
    }

    async fn sign_jwt(&self) -> Result<String> {
        let now = chrono::Utc::now();
        let claims = JwsClaims {
                iss: &self.client_email,
                sub:  &self.client_email,
                scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/devstorage.full_control",
                aud: "https://storage.googleapis.com/",
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

        // Sign the things
        let key = RsaPrivateKey::from_pkcs8_pem(&self.private_key).map_err(|e| Error::wrap(e))?;
        let signing_key = SigningKey::<Sha256>::new(key);
        let mut rng = rand::thread_rng();
        let signature = signing_key.sign_with_rng(&mut rng, &ss.as_bytes());

        Ok(format!(
            "{}.{}",
            ss,
            URL_SAFE_NO_PAD.encode(signature.to_bytes().as_ref())
        ))
    }
}

#[async_trait]
impl TokenProvider for ServiceAccountKeyFile {
    async fn fetch_token(&self) -> Result<Token> {
        let payload = self.sign_jwt().await?;
        let client = reqwest::Client::new();
        let res = client
            .post(self.token_uri)
            .form(&TokenRequest {
                grant_type: DEFAULT_OAUTH_GRANT.into(),
                assertion: payload,
            })
            .send()
            .await
            .map_err(|_| Error::new("unable to make request to oauth endpoint"))?;
        if !res.status().is_success() {
            return Err(Error::new(format!(
                "bad request with status: {}",
                res.status()
            )));
        }
        let token_response: Token = res.json().await.map_err(Error::wrap)?;

        Ok(token_response)
    }
}
