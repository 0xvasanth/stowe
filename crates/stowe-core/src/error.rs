use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("secret '{var}' not found in namespace '{namespace}'")]
    NotFound { namespace: String, var: String },

    #[error("secret '{var}' already exists in namespace '{namespace}'")]
    AlreadyExists { namespace: String, var: String },

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(String),

    #[error("toml parse error: {0}")]
    Toml(String),

    #[error("no stowe.toml found in {start} or any ancestor")]
    ManifestNotFound { start: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_message_contains_identifiers() {
        let e = Error::NotFound {
            namespace: "cognis".into(),
            var: "API_KEY".into(),
        };
        let s = format!("{}", e);
        assert!(s.contains("cognis"), "missing namespace in: {}", s);
        assert!(s.contains("API_KEY"), "missing var in: {}", s);
        assert!(s.contains("not found"), "missing 'not found' in: {}", s);
    }

    #[test]
    fn keychain_message_contains_inner() {
        let e = Error::Keychain("errSecAuthFailed".into());
        let s = format!("{}", e);
        assert!(s.contains("errSecAuthFailed"));
    }

    #[test]
    fn io_converts_via_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no file");
        let e: Error = io_err.into();
        assert!(matches!(e, Error::Io(_)));
    }
}
