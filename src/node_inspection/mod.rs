//! 节点巡检：Rust 本机采集(local)、HTTP 采集(http, 主程序→节点 API) 与 types。
//! collector 提供 K8s API 聚合辅助（容器状态计数）。

pub mod collector;
pub mod http;
pub mod local;
pub mod types;

#[allow(unused_imports)]
pub use http::{
    collect_node_inspections_http, list_node_endpoints, probe_node_endpoints_alive, NodeEndpoint,
};
pub use local::LocalCollector;
#[allow(unused_imports)]
pub use types::{
    NodeCertificate, NodeInspectionResult, NodeKernel, NodeResources, NodeSecurity, NodeServices,
};
