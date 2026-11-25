//! Fast PII and secret detection.
//!
//! A single `RegexSet` pass decides which detectors can possibly match, so clean
//! text costs one linear scan regardless of how many detectors are configured.
//! Candidate matches are then confirmed with checksum validators (Luhn, IBAN
//! mod-97, SSA rules) to keep false positives low.

use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Email,
    Phone,
    CreditCard,
    Ssn,
    Iban,
    IpAddress,
    AwsAccessKey,
    GithubToken,
    SlackToken,
    LlmApiKey,
    PrivateKey,
    Jwt,
    Password,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Email => "EMAIL",
            Kind::Phone => "PHONE",
            Kind::CreditCard => "CREDIT_CARD",
            Kind::Ssn => "SSN",
            Kind::Iban => "IBAN",
            Kind::IpAddress => "IP_ADDRESS",
            Kind::AwsAccessKey => "AWS_ACCESS_KEY",
            Kind::GithubToken => "GITHUB_TOKEN",
            Kind::SlackToken => "SLACK_TOKEN",
            Kind::LlmApiKey => "LLM_API_KEY",
            Kind::PrivateKey => "PRIVATE_KEY",
            Kind::Jwt => "JWT",
            Kind::Password => "PASSWORD",
        }
    }

    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Kind::AwsAccessKey
                | Kind::GithubToken
                | Kind::SlackToken
                | Kind::LlmApiKey
                | Kind::PrivateKey
                | Kind::Jwt
                | Kind::Password
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

type Validator = fn(&str) -> bool;

struct Detector {
    kind: Kind,
    re: Regex,
    group: usize,
    validate: Option<Validator>,
}

static DETECTORS: LazyLock<(RegexSet, Vec<Detector>)> = LazyLock::new(|| {
    let defs: [(Kind, &str, usize, Option<Validator>); 13] = [
        (
            Kind::Email,
            r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b",
            0,
            None,
        ),
        (
            Kind::Phone,
            r"(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\) ?|\b\d{3}[ .-])\d{3}[ .-]\d{4}\b|\+\d{1,3}(?:[ .-]\d{2,8}){2,4}\b|\+\d{10,14}\b",
            0,
            Some(valid_phone),
        ),
        (
            Kind::CreditCard,
            r"\b\d(?:[ -]?\d){12,18}\b",
            0,
            Some(valid_card),
        ),
        (Kind::Ssn, r"\b\d{3}-\d{2}-\d{4}\b", 0, Some(valid_ssn)),
        (
            Kind::Iban,
            r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
            0,
            Some(valid_iban),
        ),
        (
            Kind::IpAddress,
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            0,
            None,
        ),
        (
            Kind::AwsAccessKey,
            r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
            0,
            None,
        ),
        (
            Kind::GithubToken,
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
            0,
            None,
        ),
        (Kind::SlackToken, r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0, None),
        (
            Kind::LlmApiKey,
            r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{20,}",
            0,
            None,
        ),
        (
            Kind::PrivateKey,
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?-----END [A-Z ]*PRIVATE KEY-----)?",
            0,
            None,
        ),
        (
            Kind::Jwt,
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            0,
            None,
        ),
        (
            Kind::Password,
            r#"(?i)(?:\b|_)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']?([^\s"',;]{6,})"#,
            1,
            None,
        ),
    ];
    // ASCII word boundaries keep every detector on the lazy-DFA fast path.
    let ascii = |p: &str| p.replace(r"\b", r"(?-u:\b)");
    let set = RegexSet::new(defs.iter().map(|d| ascii(d.1))).expect("valid detector set");
    let detectors = defs
        .into_iter()
        .map(|(kind, pat, group, validate)| Detector {
            kind,
            re: Regex::new(&ascii(pat)).expect("valid detector"),
            group,
            validate,
        })
        .collect();
    (set, detectors)
});

/// Returns non-overlapping findings ordered by position.
pub fn scan(text: &str) -> Vec<Finding> {
    let (set, detectors) = &*DETECTORS;
    let mut found = Vec::new();
    for idx in set.matches(text).iter() {
        let d = &detectors[idx];
        let mut push = |start: usize, end: usize| {
            if d.validate.is_none_or(|v| v(&text[start..end])) {
                found.push(Finding {
                    kind: d.kind,
                    start,
                    end,
                });
            }
        };
        if d.group == 0 {
            for m in d.re.find_iter(text) {
                push(m.start(), m.end());
            }
        } else {
            for caps in d.re.captures_iter(text) {
                if let Some(m) = caps.get(d.group) {
                    push(m.start(), m.end());
                }
            }
        }
    }
    found.sort_by_key(|f| (f.start, Reverse(f.end), !f.kind.is_secret()));
    let mut last_end = 0;
    found.retain(|f| {
        let keep = f.start >= last_end;
        if keep {
            last_end = f.end;
        }
        keep
    });
    found
}

/// Replaces each finding with `[REDACTED:<KIND>]`. Findings must be sorted and non-overlapping.
pub fn redact(text: &str, findings: &[Finding]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for f in findings {
        out.push_str(&text[cursor..f.start]);
        out.push_str("[REDACTED:");
        out.push_str(f.kind.label());
        out.push(']');
        cursor = f.end;
    }
    out.push_str(&text[cursor..]);
    out
}

fn digits(s: &str) -> Vec<u32> {
    s.chars().filter_map(|c| c.to_digit(10)).collect()
}

fn valid_phone(s: &str) -> bool {
    (10..=15).contains(&digits(s).len())
}

fn valid_card(s: &str) -> bool {
    let d = digits(s);
    if !(13..=19).contains(&d.len()) || !(2..=6).contains(&d[0]) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &n)| match (i % 2, n * 2) {
            (1, x) if x > 9 => x - 9,
            (1, x) => x,
            _ => n,
        })
        .sum();
    sum.is_multiple_of(10)
}

fn valid_ssn(s: &str) -> bool {
    let (area, rest) = s.split_at(3);
    let group = &rest[1..3];
    let serial = &rest[4..];
    area != "000" && area != "666" && !area.starts_with('9') && group != "00" && serial != "0000"
}

fn valid_iban(s: &str) -> bool {
    let compact: Vec<u8> = s.bytes().filter(|b| *b != b' ').collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    let (head, tail) = compact.split_at(4);
    let mut rem: u32 = 0;
    for &b in tail.iter().chain(head) {
        let v = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'A'..=b'Z' => (b - b'A') as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<Kind> {
        scan(text).into_iter().map(|f| f.kind).collect()
    }

    #[test]
    fn detects_common_pii() {
        assert_eq!(kinds("mail jane.doe@acme.io now"), [Kind::Email]);
        assert_eq!(kinds("card 4111 1111 1111 1111 exp"), [Kind::CreditCard]);
        assert_eq!(kinds("ssn 078-05-1120"), [Kind::Ssn]);
        assert_eq!(kinds("iban GB82 WEST 1234 5698 7654 32"), [Kind::Iban]);
        assert_eq!(kinds("call (415) 555-0132"), [Kind::Phone]);
        assert_eq!(kinds("host 10.0.12.7"), [Kind::IpAddress]);
    }

    #[test]
    fn checksums_reject_lookalikes() {
        assert!(kinds("card 4111 1111 1111 1112").is_empty());
        assert!(kinds("ssn 666-12-3456 and 000-12-3456").is_empty());
        assert!(kinds("iban GB82 WEST 1234 5698 7654 33").is_empty());
    }

    #[test]
    fn detects_secrets() {
        // Fake credentials are assembled from fragments so secret scanners don't flag the repo.
        assert_eq!(
            kinds(concat!("key AK", "IAIOSFODNN7EXAMPLE")),
            [Kind::AwsAccessKey]
        );
        assert_eq!(kinds("password = hunter2hunter2"), [Kind::Password]);
        assert_eq!(
            kinds(concat!(
                "-----BEGIN RSA ",
                "PRIVATE",
                " KEY-----\nMIIabc\n-----END RSA ",
                "PRIVATE",
                " KEY-----"
            )),
            [Kind::PrivateKey]
        );
    }

    #[test]
    fn redacts_only_secret_value() {
        let text = "db password: s3cr3tValue!";
        let out = redact(text, &scan(text));
        assert_eq!(out, "db password: [REDACTED:PASSWORD]");
    }

    #[test]
    fn redaction_preserves_surrounding_text() {
        let text = "Email a@b.co or c@d.org please";
        assert_eq!(
            redact(text, &scan(text)),
            "Email [REDACTED:EMAIL] or [REDACTED:EMAIL] please"
        );
    }

    #[test]
    fn clean_text_has_no_findings() {
        assert!(scan("Summarize the Q3 roadmap in three bullet points.").is_empty());
    }
}
