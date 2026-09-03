use clap::{Parser, Subcommand, ValueEnum};
use std::str::FromStr;

use crate::utils::lang::Lang;

#[derive(Parser)]
#[command(author, version, about = "Kubernetes cluster inspection tool", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run cluster inspection
    Check {
        /// Cluster name for the report title (default: from kubeconfig or "default")
        #[arg(long = "cluster-name", value_name = "NAME")]
        cluster_name: Option<String>,

        /// Namespace(s) scope for inspection: only resources in this namespace are inspected. When unset, all namespaces are inspected.
        #[arg(short, long, value_name = "NAMESPACE")]
        namespace: Option<String>,

        /// Namespace where kube-node-inspector DaemonSet runs; used only for node-level data collection. Default: kube-system.
        #[arg(
            long = "node-inspector-namespace",
            value_name = "NAMESPACE",
            default_value = "kube-system"
        )]
        node_inspector_namespace: String,

        /// Output file path for the report; if not set, defaults to kubernetes-inspection-report-{YYYY-MM-DD-HHMMSS}.{ext}
        #[arg(short, long)]
        output: Option<String>,

        /// Output format: md, json, csv, or html (default)
        #[arg(short, long, default_value = "html")]
        format: ReportFormat,

        /// Configuration file (kcc.yaml)
        #[arg(short, long)]
        config_file: Option<String>,

        /// Kubernetes config file path (kubeconfig)
        #[arg(short = 'k', long)]
        kubeconfig: Option<String>,

        /// Check levels to show in report: "all" or comma-separated (Info, warning, critical). Default: warning,critical.
        #[arg(
            short = 'l',
            long = "level",
            value_name = "LEVELS",
            default_value = "warning,critical"
        )]
        level: String,

        /// Report language: zh (Chinese, default) or en (English)
        #[arg(
            long = "lang",
            visible_alias = "language",
            value_enum,
            default_value_t = Lang::default()
        )]
        lang: Lang,

        /// Node inspection access mode: pod_ip (default) or cluster_ip_service
        #[arg(
            long = "node-access-mode",
            value_name = "MODE",
            default_value = "pod_ip"
        )]
        node_access_mode: String,

        /// Node inspector port (used with pod_ip / service mode)
        #[arg(
            long = "node-inspector-port",
            value_name = "PORT",
            default_value_t = 9090
        )]
        node_inspector_port: u16,
    },

    /// Start the main HTTP API + Web server (default port 5005)
    Server {
        /// Listen address
        #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:5005")]
        addr: String,

        /// Web / API base path (nginx proxies this path to the server)
        #[arg(long = "web-base", value_name = "PATH", default_value = "/kcc")]
        web_base: String,

        /// Configuration file (kcc.yaml)
        #[arg(short, long = "config-file", value_name = "FILE")]
        config_file: Option<String>,

        /// Kubernetes config file path (kubeconfig)
        #[arg(short = 'k', long)]
        kubeconfig: Option<String>,

        /// Node inspection access mode（缺省时取环境变量/配置文件，默认 pod_ip）
        #[arg(long = "node-access-mode", value_name = "MODE")]
        node_access_mode: Option<String>,

        /// Node inspector port（缺省时取环境变量/配置文件，默认 9090）
        #[arg(long = "node-inspector-port", value_name = "PORT")]
        node_inspector_port: Option<u16>,
    },

    /// Start the node-inspector daemon (runs in the DaemonSet, default port 9090)
    NodeInspector {
        /// Listen address
        #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:9090")]
        addr: String,
    },
}

#[derive(Clone, Copy, ValueEnum, Debug, Default)]
#[value(rename_all = "kebab-case")]
pub enum ReportFormat {
    #[default]
    Md,
    Json,
    Csv,
    Html,
}

#[derive(Clone, ValueEnum, Debug)]
#[value(rename_all = "kebab-case")]
pub enum InspectionType {
    /// Full cluster inspection (default)
    All,
    /// Node health inspection
    Nodes,
    /// Pod status inspection
    Pods,
    /// Resource usage inspection
    Resources,
    /// Network connectivity inspection
    Network,
    /// Storage inspection
    Storage,
    /// Security configuration inspection
    Security,
    /// Control plane health inspection
    ControlPlane,
    /// Autoscaling health inspection
    Autoscaling,
    /// Batch and CronJob inspection
    Batch,
    /// Namespace policies inspection (quota/limit/pdb)
    Policies,
    /// Observability components inspection
    Observability,
    /// Upgrade readiness inspection
    Upgrade,
    /// Certificate (CSR) inspection
    Certificates,
}

impl FromStr for InspectionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "all" => Ok(InspectionType::All),
            "nodes" => Ok(InspectionType::Nodes),
            "pods" => Ok(InspectionType::Pods),
            "resources" => Ok(InspectionType::Resources),
            "network" => Ok(InspectionType::Network),
            "storage" => Ok(InspectionType::Storage),
            "security" => Ok(InspectionType::Security),
            "control" | "control-plane" => Ok(InspectionType::ControlPlane),
            "autoscaling" | "hpa" => Ok(InspectionType::Autoscaling),
            "batch" | "cron" => Ok(InspectionType::Batch),
            "policies" | "policy" => Ok(InspectionType::Policies),
            "observability" | "monitoring" => Ok(InspectionType::Observability),
            "upgrade" | "upgrade-readiness" => Ok(InspectionType::Upgrade),
            "certificates" | "certificate" | "csr" => Ok(InspectionType::Certificates),
            _ => Err(format!("Unknown inspection type: {}", s)),
        }
    }
}
