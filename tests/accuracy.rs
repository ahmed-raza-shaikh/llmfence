//! Regression gate: detection quality on the bundled datasets must not drop.

use ai_governance_gateway::eval;
use std::path::Path;

#[test]
fn pii_and_secret_detection_meets_target() {
    let report = eval::run(Path::new("datasets"), 0.5).unwrap();
    assert!(report.pii.precision() >= 0.99, "{report}");
    assert!(report.pii.recall() >= 0.99, "{report}");
}

#[test]
fn prompt_injection_detection_does_not_regress() {
    let report = eval::run(Path::new("datasets"), 0.5).unwrap();
    assert!(report.injection.f1() >= 0.95, "{report}");
    assert!(report.injection.precision() >= 0.95, "{report}");
}
