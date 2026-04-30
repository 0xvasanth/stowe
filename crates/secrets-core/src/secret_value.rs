use zeroize::Zeroize;

/// Owns a secret value. Wipes its bytes from memory on drop.
/// Never implements `Debug`. `Display` redacts and shows length only.
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_string(s: String) -> Self {
        Self(s.into_bytes())
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted: {} bytes>", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_roundtrips_via_expose() {
        let s = SecretValue::from_string("hello".to_string());
        assert_eq!(s.expose(), b"hello");
    }

    #[test]
    fn display_does_not_leak_value() {
        let s = SecretValue::from_string("super-secret".to_string());
        let displayed = format!("{}", s);
        assert!(!displayed.contains("super-secret"), "Display leaked secret: {}", displayed);
        assert!(displayed.contains("12 bytes"), "Display did not show length: {}", displayed);
    }

    #[test]
    fn len_and_empty() {
        assert!(SecretValue::from_string("".into()).is_empty());
        assert_eq!(SecretValue::from_string("abcd".into()).len(), 4);
    }
}

// Uncomment to verify Debug is NOT impl'd; this MUST fail to compile.
// #[test] fn must_not_compile() { let s = SecretValue::from_string("x".into()); let _ = format!("{:?}", s); }
