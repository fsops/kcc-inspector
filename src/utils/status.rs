//! Neutral status enums shared by the inspection, scoring, reporting and i18n
//! layers. They live here (a dependency-free module) so that `utils::lang` can
//! localize them without depending on `inspections`; `inspections::types`
//! re-exports them for backward compatibility.

use serde::{Deserialize, Serialize};

/// Status of a single check result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warning,
    Critical,
    Error,
}

/// Severity of a detected issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub enum IssueSeverity {
    #[serde(alias = "Low")]
    Info,
    #[serde(alias = "Medium")]
    Warning,
    #[serde(alias = "High")]
    Critical,
}

/// Overall cluster health classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Excellent,
    Good,
    Fair,
    Poor,
    Critical,
}
