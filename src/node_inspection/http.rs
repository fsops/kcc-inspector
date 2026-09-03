//! HTTP 节点采集：主程序直接调用每个节点巡检 Pod 的 HTTP API（pod_ip 与 cluster_ip_service 模式）。

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;
use std::time::Duration;

use crate::jobs::ProgressSink;
use crate::k8s::K8sClient;
use crate::node_inspection::collector::fill_container_state_counts;
use crate::node_inspection::types::NodeInspectionResult;

/// 节点巡检 Pod 端点信息
#[derive(Debug, Clone)]
pub struct NodeEndpoint {
    pub node_name: String,
    pub pod_name: String,
    pub pod_ip: Option<String>,
    pub alive: bool,
}

/// 列出命名空间中 kcc-inspector 巡检 Pod 的端点（名称 / IP），label 默认 `app=kcc-inspector`（可配置）。
pub async fn list_node_endpoints(
    client: &K8sClient,
    namespace: &str,
    label: &str,
) -> Result<Vec<NodeEndpoint>> {
    let pods_api: kube::Api<Pod> = client.pods(Some(namespace));
    let list_params = ListParams::default().labels(label);
    let pods = pods_api.list(&list_params).await?;
    let mut out = Vec::new();
    for pod in pods.items {
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|s| s.node_name.clone())
            .unwrap_or_default();
        let pod_name = pod.metadata.name.unwrap_or_default();
        let pod_ip = pod.status.as_ref().and_then(|s| s.pod_ip.clone());
        if node_name.is_empty() {
            continue;
        }
        out.push(NodeEndpoint {
            node_name,
            pod_name,
            pod_ip,
            alive: false,
        });
    }
    Ok(out)
}

fn build_url(ip: &str, port: u16, path: &str) -> String {
    format!("http://{}:{}{}", ip, port, path)
}

/// 通过 pod-ip 采集所有节点巡检数据。
pub async fn collect_node_inspections_http<S: ProgressSink + ?Sized>(
    client: &K8sClient,
    namespace: &str,
    port: u16,
    timeout_secs: u64,
    progress_range: Option<(f64, f64)>,
    sink: Option<&S>,
    label: &str,
) -> Result<Vec<NodeInspectionResult>> {
    let endpoints = list_node_endpoints(client, namespace, label).await?;
    let client_req = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("build http client")?;

    let mut results = Vec::new();
    let total = endpoints.len();
    for (idx, ep) in endpoints.iter().enumerate() {
        let Some(ip) = &ep.pod_ip else {
            if let Some(s) = sink {
                s.log(format!("⚠️  节点 {} 巡检 Pod 无 IP，跳过", ep.node_name));
            }
            report_node_progress(sink, progress_range, idx + 1, total);
            continue;
        };
        let url = build_url(ip, port, "/kcc/api/inspect");
        if let Some(s) = sink {
            s.log(format!("🔍 正在采集节点 {}（{}）...", ep.node_name, ip));
        }
        match client_req.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<NodeInspectionResult>().await {
                    Ok(mut r) => {
                        if r.node_name.is_empty() {
                            r.node_name = ep.node_name.clone();
                        }
                        if r.hostname.is_empty() {
                            r.hostname = r.node_name.clone();
                        }
                        results.push(r);
                        if let Some(s) = sink {
                            s.log(format!("✅ 节点 {} 采集成功", ep.node_name));
                        }
                    }
                    Err(e) => {
                        if let Some(s) = sink {
                            s.log(format!("⚠️  节点 {} 采集响应解析失败: {}", ep.node_name, e));
                        }
                    }
                }
            }
            Ok(resp) => {
                if let Some(s) = sink {
                    s.log(format!(
                        "⚠️  节点 {} 采集 HTTP {}",
                        ep.node_name,
                        resp.status()
                    ));
                }
            }
            Err(e) => {
                if let Some(s) = sink {
                    s.log(format!("⚠️  节点 {} 采集失败: {}", ep.node_name, e));
                }
            }
        }
        report_node_progress(sink, progress_range, idx + 1, total);
    }

    results.sort_by(|a, b| a.node_name.cmp(&b.node_name));
    // 容器状态计数由 K8s API 聚合填充
    fill_container_state_counts(client, &mut results).await;
    Ok(results)
}

/// 每采集完一个节点上报一次进度（在 [lo, hi] 区间内线性推进），避免进度条长时间停留在同一数值。
fn report_node_progress<S: ProgressSink + ?Sized>(
    sink: Option<&S>,
    range: Option<(f64, f64)>,
    done: usize,
    total: usize,
) {
    if let (Some((lo, hi)), Some(s), true) = (range, sink, total > 0) {
        let frac = done as f64 / total as f64;
        s.progress(lo + frac * (hi - lo), done, total);
    }
}

/// 探测每个节点巡检 Pod 的存活状态（GET /kcc/api/health），用于状态页。
pub async fn probe_node_endpoints_alive<S: ProgressSink + ?Sized>(
    client: &K8sClient,
    namespace: &str,
    port: u16,
    timeout_secs: u64,
    _sink: Option<&S>,
    label: &str,
) -> Result<Vec<NodeEndpoint>> {
    let mut endpoints = list_node_endpoints(client, namespace, label).await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;
    for ep in endpoints.iter_mut() {
        ep.alive = match &ep.pod_ip {
            Some(ip) => http
                .get(build_url(ip, port, "/kcc/api/health"))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false),
            None => false,
        };
    }
    Ok(endpoints)
}
