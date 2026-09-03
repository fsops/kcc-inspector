//! Canonical list of Kubernetes resource objects for report grouping and scoring.
//! Maps inspection issue categories (and optional rule_id) to resource keys.

use crate::inspections::types::Issue;

/// Canonical list of report resource objects (display order for scores table and Detailed Results sections).
pub const REPORT_RESOURCE_ORDER: &[&str] = &[
    "Node",
    "Pod",
    "Service",
    "Deployment",
    "Namespace",
    "PersistentVolume",
    "PersistentVolumeClaim",
    "StorageClass",
    "ClusterRole",
    "ClusterRoleBinding",
    "ServiceAccount",
    "NetworkPolicy",
    "Certificate",
    "CronJob",
    "Job",
    "HPA",
    "Policy",
    "Control Plane",
    "Observability",
    "Security",
    "Resource Management",
];

/// Maps an issue's category (and optionally rule_id) to the canonical resource object key used for grouping and scoring.
pub fn issue_to_resource_key(issue: &Issue) -> String {
    let cat = issue.category.trim();
    let rule_id = issue.rule_id.as_deref();
    match cat {
        "Container" | "Pod" => "Pod".to_string(),
        "Resource Management" => "Resource Management".to_string(),
        "Security" => "Security".to_string(),
        "Policy" => "Policy".to_string(),
        "Batch" => match rule_id {
            Some("801") | Some("802") | Some("803") => "CronJob".to_string(),
            Some("804") | Some("805") => "Job".to_string(),
            _ => "CronJob".to_string(),
        },
        "Autoscaling" => "HPA".to_string(),
        "Certificates" => "Certificate".to_string(),
        "ControlPlane" => "Control Plane".to_string(),
        "Observability" => "Observability".to_string(),
        "Node" | "Service" | "Deployment" | "Namespace" => cat.to_string(),
        "PersistentVolume" | "PersistentVolumeClaim" | "StorageClass" => cat.to_string(),
        "ClusterRole" | "ClusterRoleBinding" | "ServiceAccount" | "NetworkPolicy" => {
            cat.to_string()
        }
        _ => cat.to_string(),
    }
}
