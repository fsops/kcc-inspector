//! Types for node inspection (DaemonSet-collected) results.
//! Schema aligns with the universal node script JSON output: resources, services, security, kernel.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Single node inspection result (one JSON object per node from the DaemonSet script).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeInspectionResult {
    pub node_name: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub timestamp: String,
    /// Node local time (cluster host time) for report header/filename, e.g. 2026-02-09T18:38:22+0800
    #[serde(default)]
    pub timestamp_local: Option<String>,
    /// containerd | docker | cri-o | unknown
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub kernel_version: Option<String>,
    #[serde(default)]
    pub uptime: Option<String>,
    #[serde(default)]
    pub resources: NodeResources,
    /// Per-state container counts from docker/crictl (e.g. running, exited).
    #[serde(default)]
    pub container_state_counts: Option<HashMap<String, u32>>,
    #[serde(default)]
    pub services: NodeServices,
    #[serde(default)]
    pub security: NodeSecurity,
    #[serde(default)]
    pub stability: Option<NodeStability>,
    #[serde(default)]
    pub kernel: NodeKernel,
    /// Number of zombie processes on the node (state Z in /proc).
    #[serde(default)]
    pub zombie_count: Option<u32>,
    /// Number of checks in warning/error for summary table
    #[serde(default)]
    pub issue_count: u32,
    /// Certificates discovered from process cmdlines (path, expiry, status).
    #[serde(default)]
    pub node_certificates: Option<Vec<NodeCertificate>>,
    /// Per-mount disk usage (from df); used for Node disk usage table and 80%/90% thresholds.
    #[serde(default)]
    pub node_disks: Option<Vec<NodeDiskMount>>,
}

/// One mount point row: device, mount_point, fstype, total_g, used_g, used_pct (for report and NODE-004/NODE-005).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeDiskMount {
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub mount_point: String,
    #[serde(default)]
    pub fstype: String,
    #[serde(default)]
    pub total_g: Option<f64>,
    #[serde(default)]
    pub used_g: Option<f64>,
    #[serde(default)]
    pub used_pct: Option<f64>,
}

/// One certificate entry from node (path, expiration, days remaining, status).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeCertificate {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub expiration_date: String,
    #[serde(default)]
    pub days_remaining: i64,
    #[serde(default)]
    pub status: String,
}

/// Resource category: CPU, memory, disk, load.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeResources {
    #[serde(default)]
    pub cpu_cores: Option<u32>,
    /// CPU used (cores in use, from /proc/stat sample).
    #[serde(default)]
    pub cpu_used: Option<f64>,
    /// CPU usage percentage (0–100, from /proc/stat sample).
    #[serde(default)]
    pub cpu_used_pct: Option<f64>,
    #[serde(default)]
    pub memory_total_mib: Option<u64>,
    #[serde(default)]
    pub memory_used_mib: Option<u64>,
    #[serde(default)]
    pub memory_used_pct: Option<f64>,
    #[serde(default)]
    pub root_disk_pct: Option<f64>,
    #[serde(default)]
    pub disk_total_g: Option<f64>,
    #[serde(default)]
    pub disk_used_g: Option<f64>,
    #[serde(default)]
    pub disk_used_pct: Option<f64>,
    #[serde(default)]
    pub load_1m: Option<String>,
    #[serde(default)]
    pub load_5m: Option<String>,
    #[serde(default)]
    pub load_15m: Option<String>,
    #[serde(default)]
    pub swap_enabled: Option<bool>,
    #[serde(default)]
    pub swap_total_g: Option<f64>,
    #[serde(default)]
    pub swap_used_g: Option<f64>,
    #[serde(default)]
    pub swap_used_pct: Option<f64>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub detail: String,
}

/// Services: runtime, journald, crontab, ntp_synced, kubelet, container_runtime.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeServices {
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub journald_active: Option<bool>,
    #[serde(default)]
    pub crontab_present: Option<bool>,
    #[serde(default)]
    pub ntp_synced: Option<bool>,
    #[serde(default)]
    pub kubelet_running: Option<bool>,
    #[serde(default)]
    pub container_runtime_running: Option<bool>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub detail: String,
}

/// Security: SELinux, firewalld, IPVS, br_netfilter, overlay, nf_conntrack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeSecurity {
    #[serde(default)]
    pub selinux: Option<String>,
    #[serde(default)]
    pub firewalld_active: Option<bool>,
    #[serde(default)]
    pub ipvs_loaded: Option<bool>,
    #[serde(default)]
    pub br_netfilter_loaded: Option<bool>,
    #[serde(default)]
    pub overlay_loaded: Option<bool>,
    #[serde(default)]
    pub nf_conntrack_loaded: Option<bool>,
    #[serde(default)]
    pub nf_conntrack_count: Option<u64>,
    #[serde(default)]
    pub nf_conntrack_max: Option<u64>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub detail: String,
}

/// Network and stability: inode, OOM, file descriptors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStability {
    #[serde(default)]
    pub inode_used_pct: Option<f64>,
    #[serde(default)]
    pub oom_kill_count: Option<u64>,
    #[serde(default)]
    pub file_nr_open: Option<u64>,
    #[serde(default)]
    pub file_nr_max: Option<u64>,
}

/// Kernel: key sysctl values (2–3 keys).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeKernel {
    #[serde(default)]
    pub net_ipv4_ip_forward: Option<String>,
    #[serde(default)]
    pub vm_swappiness: Option<String>,
    #[serde(default)]
    pub net_core_somaxconn: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub detail: String,
}
