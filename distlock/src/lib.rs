use std::env;
use std::error::Error as StdError;

mod auth;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    inner: Option<BoxError>,
    msg: Option<String>,
}

impl Error {
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
}

impl Lock {
    pub fn builder() -> LockBuilder {
        LockBuilder::new()
    }

    pub async fn lock(name: String) -> Result<LockMetadata> {
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
        }
    }
}

pub struct LockMetadata {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert!(true)
    }
}
