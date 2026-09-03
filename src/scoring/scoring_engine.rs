use crate::inspections::types::*;

pub struct ScoringEngine;

impl ScoringEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate_weighted_score(&self, inspections: &[InspectionResult]) -> f64 {
        if inspections.is_empty() {
            return 0.0;
        }

        let mut total_weighted_score = 0.0;
        let mut total_weight = 0.0;

        for inspection in inspections {
            let weight = self.get_inspection_weight(&inspection.inspection_type);
            total_weighted_score += inspection.overall_score * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            total_weighted_score / total_weight
        } else {
            0.0
        }
    }

    pub fn get_health_status(&self, score: f64) -> HealthStatus {
        match score {
            s if s >= 90.0 => HealthStatus::Excellent,
            s if s >= 80.0 => HealthStatus::Good,
            s if s >= 70.0 => HealthStatus::Fair,
            s if s >= 60.0 => HealthStatus::Poor,
            _ => HealthStatus::Critical,
        }
    }

    #[allow(dead_code)]
    pub fn calculate_inspection_score(&self, checks: &[CheckResult]) -> f64 {
        if checks.is_empty() {
            return 0.0;
        }

        let mut total_weighted_score = 0.0;
        let mut total_weight = 0.0;

        for check in checks {
            let weight = self.get_check_weight(&check.name);
            let normalized_score = (check.score / check.max_score) * 100.0;

            // Apply severity penalty
            let severity_multiplier = match check.status {
                CheckStatus::Pass => 1.0,
                CheckStatus::Warning => 0.9,
                CheckStatus::Critical => 0.7,
                CheckStatus::Error => 0.5,
            };

            total_weighted_score += normalized_score * weight * severity_multiplier;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            total_weighted_score / total_weight
        } else {
            0.0
        }
    }

    fn get_inspection_weight(&self, inspection_type: &str) -> f64 {
        match inspection_type {
            "Node Health" => 2.0,
            "Pod Status" => 2.5,
            "Security Configuration" => 2.2,
            "Resource Usage" => 1.8,
            "Network Connectivity" => 1.8,
            "Storage" => 1.5,
            "Control Plane" => 2.5,
            "Autoscaling" => 1.8,
            "Batch Workloads" => 1.2,
            "Policy & Governance" => 1.6,
            "Observability" => 1.4,
            "Upgrade Readiness" => 1.7,
            _ => 1.0,
        }
    }

    #[allow(dead_code)]
    fn get_check_weight(&self, check_name: &str) -> f64 {
        match check_name {
            // Node checks
            "Node Readiness" => 3.0,
            "Node Pressure" => 2.0,

            // Pod checks
            "Pod Health" => 3.0,
            "Pod Stability" => 2.0,
            "Resource Limits" => 1.5,

            // Resource checks
            "Resource Requests" => 2.0,
            "Complete Resource Configuration" => 1.5,

            // Network checks
            "DNS Configuration" => 3.0,
            "Service Configuration" => 2.0,
            "Network Policy Coverage" => 1.5,

            // Storage checks
            "Persistent Volume Health" => 2.5,
            "PVC Binding" => 2.0,
            "Storage Class Configuration" => 1.5,

            // Security checks
            "RBAC Configuration" => 3.0,
            "Pod Security Standards" => 2.5,
            "Service Account Usage" => 1.5,

            _ => 1.0,
        }
    }

    pub fn generate_score_breakdown(
        &self,
        inspections: &[InspectionResult],
    ) -> std::collections::HashMap<String, ScoreDetails> {
        let mut breakdown = std::collections::HashMap::new();

        for inspection in inspections {
            let details = ScoreDetails {
                score: inspection.overall_score,
                weight: self.get_inspection_weight(&inspection.inspection_type),
                status: self.get_health_status(inspection.overall_score),
                check_count: inspection.checks.len(),
                critical_issues: inspection.summary.critical_checks,
                warning_issues: inspection.summary.warning_checks,
            };

            breakdown.insert(inspection.inspection_type.clone(), details);
        }

        breakdown
    }

    #[allow(dead_code)]
    pub fn calculate_improvement_score(&self, current_score: f64, issues: &[Issue]) -> f64 {
        let mut potential_improvement = 0.0;

        for issue in issues {
            let improvement = match issue.severity {
                IssueSeverity::Critical => 15.0,
                IssueSeverity::Warning => 8.0,
                IssueSeverity::Info => 2.0,
            };

            potential_improvement += improvement;
        }

        (current_score + potential_improvement).min(100.0)
    }

    #[allow(dead_code)]
    pub fn get_priority_recommendations(
        &self,
        inspections: &[InspectionResult],
    ) -> Vec<PriorityRecommendation> {
        let mut recommendations = Vec::new();

        for inspection in inspections {
            for issue in &inspection.summary.issues {
                if matches!(
                    issue.severity,
                    IssueSeverity::Critical | IssueSeverity::Warning
                ) {
                    recommendations.push(PriorityRecommendation {
                        category: issue.category.clone(),
                        description: issue.description.clone(),
                        recommendation: issue.recommendation.clone(),
                        severity: issue.severity.clone(),
                        impact_score: match issue.severity {
                            IssueSeverity::Critical => 15.0,
                            IssueSeverity::Warning => 8.0,
                            IssueSeverity::Info => 2.0,
                        },
                    });
                }
            }
        }

        // Sort by impact score descending
        recommendations.sort_by(|a, b| {
            b.impact_score
                .partial_cmp(&a.impact_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        recommendations.truncate(10); // Top 10 recommendations

        recommendations
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScoreDetails {
    pub score: f64,
    pub weight: f64,
    pub status: HealthStatus,
    pub check_count: usize,
    pub critical_issues: u32,
    pub warning_issues: u32,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PriorityRecommendation {
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub severity: IssueSeverity,
    pub impact_score: f64,
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}
