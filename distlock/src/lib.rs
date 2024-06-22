use std::error::Error as StdError;

#[derive(Debug)]
pub struct Error {
    kind: String, // TODO
    inner: Option<BoxError>,
    msg: Option<String>,
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
    client: String, // TODO
    logger: String, // TODO
    bucket: String,
}

impl Lock {
    pub fn builder() -> LockBuilder{
        LockBuilder::new()
    }

    pub fn lock(name: String) -> Result<LockMetadata>{
        Ok(LockMetadata{})
    }

    pub fn unlock(name: String) -> Option<Error>{
        None
    }
}

pub struct LockBuilder {
}

impl LockBuilder {
    pub fn new() -> Self {
        LockBuilder{}
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
