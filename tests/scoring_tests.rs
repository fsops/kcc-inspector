use chrono::Utc;
use kcc::inspections::types::*;
use kcc::scoring::scoring_engine::ScoringEngine;

#[test]
fn test_scoring_engine_calculation() {
    let engine = ScoringEngine::new();

    // Create test inspection result
    let inspection = InspectionResult {
        inspection_type: "Test".to_string(),
        timestamp: Utc::now(),
        overall_score: 85.0,
        checks: vec![CheckResult {
            name: "Test Check".to_string(),
            description: "Test description".to_string(),
            status: CheckStatus::Pass,
            score: 85.0,
            max_score: 100.0,
            details: None,
            recommendations: vec![],
        }],
        summary: InspectionSummary {
            total_checks: 1,
            passed_checks: 1,
            warning_checks: 0,
            critical_checks: 0,
            error_checks: 0,
            issues: vec![],
        },
        certificate_expiries: None,
        pod_container_states: None,
        namespace_summary_rows: None,
    };

    let inspections = vec![inspection];
    let weighted_score = engine.calculate_weighted_score(&inspections);

    assert!(weighted_score > 0.0);
    assert!(weighted_score <= 100.0);
}

#[test]
fn test_health_status_calculation() {
    let engine = ScoringEngine::new();

    assert!(matches!(
        engine.get_health_status(95.0),
        HealthStatus::Excellent
    ));
    assert!(matches!(engine.get_health_status(85.0), HealthStatus::Good));
    assert!(matches!(engine.get_health_status(75.0), HealthStatus::Fair));
    assert!(matches!(engine.get_health_status(65.0), HealthStatus::Poor));
    assert!(matches!(
        engine.get_health_status(50.0),
        HealthStatus::Critical
    ));
}

#[test]
fn test_check_scoring() {
    let engine = ScoringEngine::new();

    let checks = vec![
        CheckResult {
            name: "Node Readiness".to_string(),
            description: "Test".to_string(),
            status: CheckStatus::Pass,
            score: 100.0,
            max_score: 100.0,
            details: None,
            recommendations: vec![],
        },
        CheckResult {
            name: "Pod Health".to_string(),
            description: "Test".to_string(),
            status: CheckStatus::Warning,
            score: 80.0,
            max_score: 100.0,
            details: None,
            recommendations: vec![],
        },
    ];

    let score = engine.calculate_inspection_score(&checks);
    assert!(score > 0.0);
    assert!(score < 100.0); // Should be less than 100 due to warning
}
