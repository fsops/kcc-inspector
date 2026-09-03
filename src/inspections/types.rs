use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// `CheckStatus`, `IssueSeverity` and `HealthStatus` live in the dependency-free
// `crate::utils::status` module (neutral layer, used by inspections/scoring/
// reporting/i18n alike). They are re-exported here so existing imports such as
// `use crate::inspections::types::*` keep working unchanged. New code should
// import them from `crate::utils::status` directly.
pub use crate::utils::status::{CheckStatus, HealthStatus, IssueSeverity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub inspection_type: String,
    pub timestamp: DateTime<Utc>,
    pub overall_score: f64,
    pub checks: Vec<CheckResult>,
    pub summary: InspectionSummary,
    /// TLS certificate expiry rows (e.g. from Certificates inspection). Rendered as a table in the report.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub certificate_expiries: Option<Vec<CertificateExpiryRow>>,
    /// Pod/container abnormal state rows (Pod Status inspection). Rendered as a table.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pod_container_states: Option<Vec<PodContainerStateRow>>,
    /// Namespace summary table (Namespace inspection). Rendered as a table.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub namespace_summary_rows: Option<Vec<NamespaceSummaryRow>>,
}

/// One row for the namespace summary table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceSummaryRow {
    pub name: String,
    pub pod_count: u32,
    pub deployment_count: u32,
    pub has_network_policy: bool,
    pub has_resource_quota: bool,
    pub has_limit_range: bool,
}

/// One row for the pod container state table (Pod, Container, State/Reason, Message or exit code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodContainerStateRow {
    pub pod_ref: String,
    pub container_name: String,
    pub state_kind: String,
    pub reason: String,
    pub detail: String,
}

/// One row for the database middleware pod table (image-based detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMiddlewareRow {
    pub namespace: String,
    pub pod_name: String,
    /// Matching container image (first match).
    pub image: String,
    /// Whether all containers in the pod are ready.
    pub ready: bool,
    /// Sum of restart counts across containers (init + main).
    pub restart_count: u32,
}

/// One row for the TLS certificate expiry table (Secret, subject, expiry, days until expiry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateExpiryRow {
    pub secret_namespace: String,
    pub secret_name: String,
    pub subject_or_cn: String,
    pub expiry_utc: String,
    pub days_until_expiry: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub description: String,
    pub status: CheckStatus,
    pub score: f64,
    pub max_score: f64,
    pub details: Option<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionSummary {
    pub total_checks: u32,
    pub passed_checks: u32,
    pub warning_checks: u32,
    pub critical_checks: u32,
    pub error_checks: u32,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: IssueSeverity,
    pub category: String,
    pub description: String,
    pub resource: Option<String>,
    pub recommendation: String,
    /// Optional rule/check ID for grouping and documentation reference.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule_id: Option<String>,
}

/// One row for the recent cluster events table (Warning/Error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub namespace: String,
    pub object_ref: String,
    pub event_type: String,
    pub reason: String,
    pub message: String,
    pub last_seen: String,
}

/// One row for the node conditions table: Node | Ready | MemoryPressure | DiskPressure | PIDPressure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConditionsRow {
    pub node_name: String,
    pub ready: String,
    pub memory_pressure: String,
    pub disk_pressure: String,
    pub pid_pressure: String,
}

/// One row for the node list table in the report (name, OS, arch, kubelet, ready, pod count).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRow {
    pub name: String,
    pub operating_system: String,
    pub architecture: String,
    pub kubelet_version: String,
    pub ready: bool,
    /// Number of pods scheduled on this node.
    pub pod_count: u32,
    /// Node InternalIP from status.addresses (for Node General Information table).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_address: Option<String>,
    /// OS image from Node.status.nodeInfo (kubectl OS-IMAGE); preferred for report when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os_image: Option<String>,
    /// Kernel version from Node.status.nodeInfo (kubectl KERNEL-VERSION); preferred for report when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kernel_version: Option<String>,
    /// Container runtime from Node.status.nodeInfo (e.g. containerd://2.1.5).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub container_runtime_version: Option<String>,
}

/// Pod phase counts for cluster overview (from List Pods).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PodPhaseBreakdown {
    pub running: u32,
    pub pending: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub unknown: u32,
}

/// Workload controller counts and ready counts (Deployments, StatefulSets, DaemonSets).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkloadSummary {
    pub deployments_total: u32,
    pub deployments_ready: u32,
    pub statefulsets_total: u32,
    pub statefulsets_ready: u32,
    pub daemonsets_total: u32,
    pub daemonsets_ready: u32,
}

/// Storage summary: PV, PVC, StorageClass counts (from API).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageSummary {
    pub pv_total: u32,
    pub pvc_total: u32,
    pub pvc_bound: u32,
    pub storage_class_count: u32,
    pub has_default_storage_class: bool,
}

/// Cluster-level overview: version, node counts, OS/arch summary, and optional resource totals.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterOverview {
    /// API server version (e.g. "1.28.x"), if available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cluster_version: Option<String>,
    /// Total number of nodes.
    pub node_count: u32,
    /// Number of nodes with Ready condition True.
    pub ready_node_count: u32,
    /// Total number of pods in the cluster (all namespaces).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pod_count: Option<u32>,
    /// Human-readable summary of node OS/arch/kubelet (e.g. "Linux, 4 nodes, amd64, kubelet 1.28.x").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_summary: Option<String>,
    /// Aggregate capacity/allocatable across nodes, if collected.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_resources: Option<NodeResourceSummary>,
    /// Per-node list (name, OS, arch, kubelet, ready).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_list: Option<Vec<NodeRow>>,
    /// Whether node usage (metrics) was available; if false, report can show "metrics-server required".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metrics_available: Option<bool>,
    /// Per-node CPU/memory usage from metrics.k8s.io (when metrics-server is available).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_usage: Option<Vec<NodeUsageRow>>,
    /// Total CPU usage in cores (sum of node usage; for report totals).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total_usage_cpu_cores: Option<f64>,
    /// Total memory usage in Gi (sum of node usage; for report totals).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total_usage_memory_gi: Option<f64>,
    /// Per-node conditions: Ready, MemoryPressure, DiskPressure, PIDPressure.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_conditions: Option<Vec<NodeConditionsRow>>,
    /// Pod phase breakdown (running, pending, succeeded, failed, unknown).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pod_phase_breakdown: Option<PodPhaseBreakdown>,
    /// Total namespace count.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub namespace_count: Option<u32>,
    /// Workload controller summary (Deployments, StatefulSets, DaemonSets).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workload_summary: Option<WorkloadSummary>,
    /// Storage summary (PV, PVC, StorageClass).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub storage_summary: Option<StorageSummary>,
    /// Cluster age in days (from oldest node creation_timestamp to now); approximate.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cluster_age_days: Option<u64>,
    /// Per-container usage vs requests/limits (notable rows only: high usage, low usage, or no request/limit). From metrics-server + Pod spec; omitted when metrics unavailable.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub container_usage_notable: Option<Vec<ContainerUsageRow>>,
}

/// One row for the container resource usage table (notable only: high usage, low usage, or no request/limit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerUsageRow {
    pub namespace: String,
    pub pod_name: String,
    pub container_name: String,
    /// CPU used in millicores (from metrics-server); 0 if missing.
    pub cpu_used_m: u64,
    /// CPU request in millicores (from Pod spec); 0 if not set.
    pub cpu_request_m: u64,
    /// CPU limit in millicores (from Pod spec); 0 if not set.
    pub cpu_limit_m: u64,
    /// Memory used in MiB (from metrics-server); 0 if missing.
    pub mem_used_mib: u64,
    /// Memory request in MiB (from Pod spec); 0 if not set.
    pub mem_request_mib: u64,
    /// Memory limit in MiB (from Pod spec); 0 if not set.
    pub mem_limit_mib: u64,
    /// Why this row is notable: "high_usage" | "low_usage" | "no_request_no_limit".
    pub notable_reason: String,
}

/// Per-node resource usage from metrics-server (allocatable + usage + % for CPU/Memory/Disk per node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeUsageRow {
    pub node_name: String,
    /// Allocatable CPU in cores (for this node).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allocatable_cpu_cores: Option<f64>,
    /// CPU usage in cores (current).
    pub cpu_usage: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu_pct: Option<f64>,
    /// Allocatable memory in Gi (for this node).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allocatable_memory_gi: Option<f64>,
    /// Memory usage in Gi (current).
    pub memory_usage: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub memory_pct: Option<f64>,
    /// Allocatable ephemeral-storage in Gi (from node status; metrics-server does not provide disk usage).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub disk_allocatable_gi: Option<f64>,
    /// Disk usage in Gi (N/A from metrics-server; reserved for future).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub disk_usage_gi: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub disk_pct: Option<f64>,
}

/// Aggregate node capacity and allocatable (CPU/memory as display strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeResourceSummary {
    pub capacity_cpu: String,
    pub capacity_memory: String,
    pub allocatable_cpu: String,
    pub allocatable_memory: String,
    /// Total allocatable ephemeral-storage in Gi (sum across nodes).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allocatable_disk_gi: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterReport {
    pub cluster_name: String,
    pub report_id: String,
    pub timestamp: DateTime<Utc>,
    pub overall_score: f64,
    pub inspections: Vec<InspectionResult>,
    pub executive_summary: ExecutiveSummary,
    /// Optional cluster overview (version, nodes, resources) for report header.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cluster_overview: Option<ClusterOverview>,
    /// 每个节点的巡检结果（来自 kcc-inspector DaemonSet，JSON 格式）。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub node_inspection_results: Option<Vec<super::super::node_inspection::NodeInspectionResult>>,
    /// Cluster host local time for report header (from first node's timestamp_local).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display_timestamp: Option<String>,
    /// Timestamp for filename (YYYY-MM-DD-HHMMSS) in cluster local time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display_timestamp_filename: Option<String>,
    /// Recent cluster events (Warning/Error), for report section.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recent_events: Option<Vec<EventRow>>,
    /// Database middleware pods (image-based detection), for report section.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub db_middleware: Option<Vec<DbMiddlewareRow>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub health_status: HealthStatus,
    pub key_findings: Vec<String>,
    pub priority_recommendations: Vec<String>,
    pub score_breakdown: HashMap<String, f64>,
}
