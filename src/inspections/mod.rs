pub mod autoscaling;
pub mod batch;
pub mod certificates;
pub mod control_plane;
pub mod issue_codes;
pub mod namespace_summary;
pub mod network;
pub mod nodes;
pub mod observability;
pub mod pods;
pub mod policies;
pub mod resources;
pub mod runner;
pub mod security;
pub mod storage;
pub mod types;
pub mod upgrade;

pub use runner::InspectionRunner;
#[allow(unused_imports)]
pub use types::*;

/// 评分时排除的命名空间（k8s 自身服务不参与评分；巡检/问题列表仍会包含这些容器）。
pub fn is_scoring_excluded_namespace(ns: &str) -> bool {
    matches!(ns, "kube-system" | "cilium-secrets")
}
