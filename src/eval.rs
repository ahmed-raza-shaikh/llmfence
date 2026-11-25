//! Offline accuracy evaluation against labeled JSONL datasets.

use crate::detect::{self, Kind};
use crate::injection;
use anyhow::Context;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Metrics {
    pub tp: usize,
    pub fp: usize,
    pub fn_: usize,
    pub tn: usize,
}

impl Metrics {
    fn ratio(num: usize, den: usize) -> f64 {
        if den == 0 {
            1.0
        } else {
            num as f64 / den as f64
        }
    }
    pub fn precision(&self) -> f64 {
        Self::ratio(self.tp, self.tp + self.fp)
    }
    pub fn recall(&self) -> f64 {
        Self::ratio(self.tp, self.tp + self.fn_)
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
    pub fn accuracy(&self) -> f64 {
        Self::ratio(self.tp + self.tn, self.tp + self.tn + self.fp + self.fn_)
    }
}

#[derive(Deserialize)]
struct PiiCase {
    text: String,
    labels: BTreeSet<Kind>,
}

#[derive(Deserialize)]
struct InjectionCase {
    text: String,
    injection: bool,
}

#[derive(Debug, Default)]
pub struct Report {
    pub pii_cases: usize,
    pub pii: Metrics,
    pub per_kind: BTreeMap<Kind, Metrics>,
    pub injection_cases: usize,
    pub injection: Metrics,
    /// Human-readable description of every misclassified case.
    pub errors: Vec<String>,
}

fn read_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<Vec<T>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    raw.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str(l).with_context(|| format!("{}:{}", path.display(), i + 1))
        })
        .collect()
}

pub fn run(dir: &Path, injection_threshold: f32) -> anyhow::Result<Report> {
    let mut report = Report::default();

    let pii: Vec<PiiCase> = read_jsonl(&dir.join("pii.jsonl"))?;
    report.pii_cases = pii.len();
    for case in &pii {
        let predicted: BTreeSet<Kind> = detect::scan(&case.text)
            .into_iter()
            .map(|f| f.kind)
            .collect();
        for kind in predicted.union(&case.labels) {
            let m = report.per_kind.entry(*kind).or_default();
            match (predicted.contains(kind), case.labels.contains(kind)) {
                (true, true) => m.tp += 1,
                (true, false) => m.fp += 1,
                (false, true) => m.fn_ += 1,
                (false, false) => unreachable!(),
            }
        }
        if predicted.is_empty() && case.labels.is_empty() {
            report.pii.tn += 1;
        }
        if predicted != case.labels {
            report.errors.push(format!(
                "pii: expected {:?}, got {:?}: {}",
                case.labels, predicted, case.text
            ));
        }
    }
    for m in report.per_kind.values() {
        report.pii.tp += m.tp;
        report.pii.fp += m.fp;
        report.pii.fn_ += m.fn_;
    }

    let inj: Vec<InjectionCase> = read_jsonl(&dir.join("injection.jsonl"))?;
    report.injection_cases = inj.len();
    for case in &inj {
        let verdict = injection::score(&case.text);
        let flagged = verdict.score >= injection_threshold;
        if flagged != case.injection {
            report.errors.push(format!(
                "injection: expected {}, score {:.2} {:?}: {}",
                case.injection, verdict.score, verdict.rules, case.text
            ));
        }
        let m = &mut report.injection;
        match (flagged, case.injection) {
            (true, true) => m.tp += 1,
            (true, false) => m.fp += 1,
            (false, true) => m.fn_ += 1,
            (false, false) => m.tn += 1,
        }
    }
    Ok(report)
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "| Detector | Cases | Precision | Recall | F1 |")?;
        writeln!(f, "|---|---|---|---|---|")?;
        let row = |f: &mut fmt::Formatter<'_>, name: &str, n: String, m: &Metrics| {
            writeln!(
                f,
                "| {name} | {n} | {:.4} | {:.4} | {:.4} |",
                m.precision(),
                m.recall(),
                m.f1()
            )
        };
        row(
            f,
            "**PII & secrets (micro)**",
            self.pii_cases.to_string(),
            &self.pii,
        )?;
        for (kind, m) in &self.per_kind {
            row(f, kind.label(), (m.tp + m.fn_).to_string(), m)?;
        }
        row(
            f,
            "**Prompt injection**",
            self.injection_cases.to_string(),
            &self.injection,
        )?;
        writeln!(
            f,
            "\nPrompt-injection accuracy: {:.4}",
            self.injection.accuracy()
        )?;
        if !self.errors.is_empty() {
            writeln!(f, "\nMisclassified ({}):", self.errors.len())?;
            for e in &self.errors {
                writeln!(f, "- {e}")?;
            }
        }
        Ok(())
    }
}
