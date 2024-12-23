#![allow(unused)]

use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;

mod auth;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: Option<BoxError>,
    msg: Option<String>,
}

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Error {
            msg: Some(msg.into()),
            inner: None,
            kind: ErrorKind::Other,
        }
    }

    fn wrap_msg(msg: impl Into<String>, error: BoxError) -> Self {
        Error {
            msg: Some(msg.into()),
            inner: Some(error),
            kind: ErrorKind::Other,
        }
    }

    fn wrap(error: impl Into<BoxError>) -> Self {
        Error {
            msg: None,
            inner: Some(error.into()),
            kind: ErrorKind::Other,
        }
    }

    fn lock_held(msg: impl Into<String>, error: Option<BoxError>) -> Self {
        Error {
            msg: Some(msg.into()),
            inner: error,
            kind: ErrorKind::LockHeld,
        }
    }

    pub fn is_lock_held(&self) -> bool {
        self.kind == ErrorKind::LockHeld
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
enum ErrorKind {
    /// An error indicating the lock requested is already held.
    LockHeld,
    /// An error related to make network requests or a failed request.
    /// A custom error that does not currently fall into other categories.
    Other,
}

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(inner) = &self.inner {
            inner.fmt(f)
        } else if let Some(msg) = &self.msg {
            write!(f, "{}", msg)
        } else {
            write!(f, "unknown error")
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Lock {
    client: reqwest::Client,
    bucket: String,
    token_provider: Box<dyn auth::TokenProvider>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectMetadata {
    bucket: String,
    custom_time: String,
    name: String,
}

impl Lock {
    pub fn builder() -> LockBuilder {
        LockBuilder::new()
    }

    pub async fn lock(&self, name: impl Into<String>) -> Result<LockMetadata> {
        let name = name.into();
        // TODO: switch this to multipart and upload a custom timestamp
        let query: [(&str, &str); 3] = [
            ("uploadType", "media"),
            ("ifGenerationMatch", "0"),
            ("name", &name),
        ];

        let metadata = ObjectMetadata {
            bucket: self.bucket.clone(),
            custom_time: chrono::Utc::now().to_rfc3339(),
            name: name.clone(),
        };

        let metadata = serde_json::to_vec(&metadata).map_err(Error::wrap)?;
        let mut content_headers = http::HeaderMap::with_capacity(1);
        content_headers.insert("Content-Type", "text/plain; charset=utf-8".parse().unwrap());

        let form = Form::new()
            .part("body", Part::bytes(metadata).mime_str("application/json").map_err(Error::wrap)?)
            .part("media", Part::text("lock").headers(content_headers));

        let tok = self.token_provider.fetch_token().await?;

        let resp = self
            .client
            .post(&format!(
                "https://storage.googleapis.com/upload/storage/v1/b/{}/o",
                self.bucket,
            ))
            .query(&query)
            .bearer_auth(tok.access_token)
            .multipart(form)
            .send()
            .await
            .map_err(|e| Error::wrap(e))?;
        println!("{}", resp.status());
        println!("{}", resp.text().await.unwrap());
        Ok(LockMetadata {})
    }

    pub async fn unlock(name: String) -> Option<Error> {
        None
    }
}

pub struct LockBuilder {
    gcs_bucket: String,
}

impl LockBuilder {
    pub fn new() -> Self {
        let bucket = std::env::var("GOOGLE_CLOUD_BUCKET").unwrap_or("".into());
        LockBuilder {
            gcs_bucket: bucket.into(),
        }
    }

    pub fn gcs_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.gcs_bucket = bucket.into();
        self
    }

    pub fn build(self) -> Lock {
        Lock {
            client: reqwest::Client::new(),
            bucket: self.gcs_bucket,
            // TODO(codyoss): return a Result here
            token_provider: auth::new_token_provider().unwrap(),
        }
    }
}

pub struct LockMetadata {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::main]
    #[test]
    async fn test_refresher_returns_same_value() {
        let lock = Lock::builder().gcs_bucket("codyoss-playground").build();
        let metadata = lock.lock("test2").await.unwrap();
    }
}
