//! Secret-shaped string detection, shared by `jsminer` (scripts) and `secrets` (every
//! captured response body).
//!
//! The patterns are the shapes that are unmistakable — an `AKIA…` access key is an AWS
//! access key and nothing else — plus one deliberately broader `key = "…"` assignment,
//! marked as the weaker signal it is. A match is a shape, not a proven-live credential;
//! the finding is the lead, and the fix is always the same: confirm and rotate.

use regex::Regex;

/// One secret-shaped string, with the kind of secret it matched.
pub struct SecretHit {
    pub kind: &'static str,
    pub matched: String,
}

/// Compiled secret patterns, built once and reused.
pub struct SecretScanner {
    patterns: Vec<(&'static str, Regex)>,
}

impl SecretScanner {
    pub fn new() -> Self {
        // Each `.expect` is on a literal pattern the tests below compile, so it cannot fire
        // at runtime.
        let patterns = [
            ("aws-access-key", r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}"),
            ("google-api-key", r"AIza[0-9A-Za-z_\-]{35}"),
            ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
            ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
            ("stripe-key", r"[sr]k_live_[A-Za-z0-9]{20,}"),
            ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            (
                "jwt",
                r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            ),
            (
                "hardcoded-secret-assignment",
                r#"(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|auth[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-.]{12,}["']"#,
            ),
        ]
        .into_iter()
        .map(|(kind, pattern)| (kind, Regex::new(pattern).expect("static secret pattern")))
        .collect();
        SecretScanner { patterns }
    }

    /// Every secret-shaped string in `text`.
    pub fn scan(&self, text: &str) -> Vec<SecretHit> {
        let mut out = Vec::new();
        for (kind, re) in &self.patterns {
            for m in re.find_iter(text) {
                out.push(SecretHit {
                    kind,
                    matched: m.as_str().to_string(),
                });
            }
        }
        out
    }
}

/// A short, display-safe form of a matched secret, truncated so a long value does not
/// flood the terminal (and a private key is named, not dumped).
pub fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        format!("{}…", value.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        let _ = SecretScanner::new();
    }

    #[test]
    fn vendor_secrets_match_and_ordinary_code_does_not() {
        let s = SecretScanner::new();
        // Assembled from parts so no full key literal lives in this source (push protection).
        let aws = format!("AK{}{}", "IA", "IOSFODNN7EXAMPLE");
        let stripe = format!("sk_{}_{}", "live", "0123456789abcdef0123456789");
        let text = format!("const a=\"{aws}\"; const s=\"{stripe}\"; function totalTokens(){{}}");
        let kinds: Vec<&str> = s.scan(&text).iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&"aws-access-key"), "{kinds:?}");
        assert!(kinds.contains(&"stripe-key"), "{kinds:?}");
        assert!(!kinds.contains(&"hardcoded-secret-assignment"), "{kinds:?}");
    }

    #[test]
    fn a_hardcoded_assignment_is_caught_as_the_weaker_signal() {
        let s = SecretScanner::new();
        let kinds: Vec<&str> = s
            .scan(r#"{"api_key": "s3cr3t_value_12345"}"#)
            .iter()
            .map(|h| h.kind)
            .collect();
        assert!(kinds.contains(&"hardcoded-secret-assignment"), "{kinds:?}");
    }

    #[test]
    fn truncate_keeps_short_values_and_shortens_long_ones() {
        assert_eq!(truncate("short", 56), "short");
        assert_eq!(
            truncate(&"x".repeat(100), 10),
            format!("{}…", "x".repeat(10))
        );
    }
}
