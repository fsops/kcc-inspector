use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::ListParams;
use std::collections::HashMap;
use uuid::Uuid;

use super::types::{
    CheckResult, CheckStatus, ClusterOverview, ClusterReport, ContainerUsageRow, DbMiddlewareRow,
    EventRow, ExecutiveSummary, HealthStatus, InspectionResult, InspectionSummary, Issue,
    IssueSeverity, NodeConditionsRow, NodeResourceSummary, NodeRow, NodeUsageRow,
    PodPhaseBreakdown, StorageSummary, WorkloadSummary,
};
use super::{
    autoscaling, batch, certificates, control_plane, namespace_summary, network, nodes,
    observability, pods, policies, resources, security, storage, upgrade,
};
use crate::cli::InspectionType;
use crate::config::{NodeAccess, NodeAccessMode};
use crate::jobs::ProgressSink;
use crate::k8s::K8sClient;
use crate::node_inspection::{collect_node_inspections_http, NodeInspectionResult};
use crate::utils::lang::Lang;
use crate::utils::resource_quantity::{parse_cpu_str, parse_memory_str};

fn parse_cpu_quantity(q: Option<&Quantity>) -> Option<i64> {
    q.and_then(|q| parse_cpu_str(q.0.as_str()))
}

fn parse_memory_quantity(q: Option<&Quantity>) -> Option<i64> {
    q.and_then(|q| parse_memory_str(q.0.as_str()))
}

fn format_cpu_millis(millis: i64) -> String {
    if millis % 1000 == 0 {
        format!("{}", millis / 1000)
    } else {
        format!("{}m", millis)
    }
}

fn format_memory_bytes(b: i64) -> String {
    const GIB: i64 = 1024 * 1024 * 1024;
    const MIB: i64 = 1024 * 1024;
    const KIB: i64 = 1024;
    if b >= GIB && b % GIB == 0 {
        format!("{}Gi", b / GIB)
    } else if b >= MIB && b % MIB == 0 {
        format!("{}Mi", b / MIB)
    } else if b >= KIB && b % KIB == 0 {
        format!("{}Ki", b / KIB)
    } else {
        format!("{}", b)
    }
}

/// Format CPU millicores as cores for display (e.g. 330 -> "0.33", 1500 -> "1.5").
fn format_cpu_cores(millis: i64) -> String {
    if millis % 1000 == 0 {
        format!("{}", millis / 1000)
    } else {
        format!("{:.2}", millis as f64 / 1000.0)
    }
}

/// Format memory bytes as Gi for display (e.g. 2147483648 -> "2.0Gi").
fn format_memory_gi(bytes: i64) -> String {
    const GIB: i64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1}Gi", bytes as f64 / GIB as f64)
    } else {
        format_memory_bytes(bytes)
    }
}

pub struct InspectionRunner {
    client: K8sClient,
    lang: Lang,
}

impl InspectionRunner {
    pub fn new(client: K8sClient) -> Self {
        Self {
            client,
            lang: Lang::default(),
        }
    }

    /// Set the report language; localized data strings (descriptions,
    /// recommendations, details) are produced in this language. Default: Chinese.
    pub fn with_lang(mut self, lang: Lang) -> Self {
        self.lang = lang;
        self
    }

    /// 可指定节点采集方式并向外发送进度/日志（CLI 与 server 共用）。
    #[allow(clippy::too_many_arguments)]
    pub async fn run_inspections_ex<S: ProgressSink + ?Sized>(
        &self,
        inspection_type: InspectionType,
        namespace: Option<&str>,
        node_inspector_namespace: &str,
        node_inspector_label: &str,
        cluster_name_override: Option<&str>,
        access: &NodeAccess,
        sink: Option<&S>,
    ) -> Result<ClusterReport> {
        let log = |sink: Option<&S>, line: String| {
            if let Some(s) = sink {
                s.log(line);
            } else {
                println!("{}", line);
            }
        };
        let mut inspections = Vec::new();
        let total_steps: usize = match inspection_type {
            InspectionType::All => 15,
            _ => 2,
        };
        let mut step: usize = 0;

        match inspection_type {
            // 逻辑顺序：基础设施 → 存储与资源 → 工作负载 → 安全与策略 → 运维
            InspectionType::All => {
                log(sink, "▶ 执行节点健康检查".to_string());
                inspections.push(self.run_node_inspection().await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行控制平面检查".to_string());
                inspections.push(self.run_control_plane_inspection().await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行网络检查".to_string());
                inspections.push(self.run_network_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行存储检查".to_string());
                inspections.push(self.run_storage_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行资源检查".to_string());
                inspections.push(self.run_resource_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行 Pod 检查".to_string());
                inspections.push(self.run_pod_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行自动伸缩检查".to_string());
                inspections.push(self.run_autoscaling_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行批处理检查".to_string());
                inspections.push(self.run_batch_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行安全检查".to_string());
                inspections.push(self.run_security_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行策略检查".to_string());
                inspections.push(self.run_policy_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行可观测性检查".to_string());
                inspections.push(self.run_observability_inspection(namespace).await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行命名空间摘要".to_string());
                inspections.push(self.run_namespace_summary_inspection().await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行证书检查".to_string());
                inspections.push(self.run_certificate_inspection().await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
                log(sink, "▶ 执行升级就绪检查".to_string());
                inspections.push(self.run_upgrade_readiness_inspection().await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(step as f64 / total_steps as f64 * 90.0, step, total_steps);
                }
            }
            InspectionType::Nodes => {
                log(sink, "▶ 执行节点健康检查".to_string());
                inspections.push(self.run_node_inspection().await?);
                step += 1;
                if let Some(s) = sink {
                    s.progress(50.0, step, total_steps);
                }
            }
            InspectionType::Pods => {
                log(sink, "▶ 执行 Pod 检查".to_string());
                inspections.push(self.run_pod_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Resources => {
                log(sink, "▶ 执行资源检查".to_string());
                inspections.push(self.run_resource_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Network => {
                log(sink, "▶ 执行网络检查".to_string());
                inspections.push(self.run_network_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Storage => {
                log(sink, "▶ 执行存储检查".to_string());
                inspections.push(self.run_storage_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Security => {
                log(sink, "▶ 执行安全检查".to_string());
                inspections.push(self.run_security_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::ControlPlane => {
                log(sink, "▶ 执行控制平面检查".to_string());
                inspections.push(self.run_control_plane_inspection().await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Autoscaling => {
                log(sink, "▶ 执行自动伸缩检查".to_string());
                inspections.push(self.run_autoscaling_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Batch => {
                log(sink, "▶ 执行批处理检查".to_string());
                inspections.push(self.run_batch_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Policies => {
                log(sink, "▶ 执行策略检查".to_string());
                inspections.push(self.run_policy_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Observability => {
                log(sink, "▶ 执行可观测性检查".to_string());
                inspections.push(self.run_observability_inspection(namespace).await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Upgrade => {
                log(sink, "▶ 执行升级就绪检查".to_string());
                inspections.push(self.run_upgrade_readiness_inspection().await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
            InspectionType::Certificates => {
                log(sink, "▶ 执行证书检查".to_string());
                inspections.push(self.run_certificate_inspection().await?);
                if let Some(s) = sink {
                    s.progress(50.0, 1, 2);
                }
            }
        }

        if let Some(s) = sink {
            if s.cancelled() {
                return Err(anyhow::anyhow!("巡检已取消"));
            }
        }

        let mut overall_score = self.calculate_overall_score(&inspections);
        let mut executive_summary = self.generate_executive_summary(&inspections, overall_score);
        let cluster_name = cluster_name_override
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.client.cluster_name().unwrap_or("default").to_string());

        let cluster_overview = self.fetch_cluster_overview().await.ok();
        let recent_events = self
            .fetch_recent_events(50)
            .await
            .ok()
            .filter(|v| !v.is_empty());
        let db_middleware = self
            .collect_db_middleware()
            .await
            .ok()
            .filter(|v| !v.is_empty());

        // 仅在进行完整巡检或仅节点巡检时，采集每个节点的巡检 JSON。
        // DaemonSet 在 node_inspector_namespace（默认 kube-system）中查找；巡检作用域为 namespace。
        // 节点采集阶段在 [lo, hi] 区间内按节点线性上报进度：
        //   All   巡检步骤 0..90% → 采集 90..99%
        //   Nodes 巡检步骤 0..50% → 采集 55..97%
        // 保证进度单调递增（不再回退到 50% 并长时间卡住）。
        let progress_range: Option<(f64, f64)> = match inspection_type {
            InspectionType::All => Some((90.0, 99.0)),
            InspectionType::Nodes => Some((55.0, 97.0)),
            _ => None,
        };

        let node_inspection_results: Option<Vec<NodeInspectionResult>> = match inspection_type {
            InspectionType::All | InspectionType::Nodes => {
                log(
                    sink,
                    format!(
                        "🔌 正在通过节点巡检 API（{}:{}/kcc/api/inspect）采集节点数据...",
                        match access.mode {
                            NodeAccessMode::PodIp => "pod_ip".to_string(),
                            NodeAccessMode::ClusterIpService => "service".to_string(),
                        },
                        access.port
                    ),
                );
                let collected = collect_node_inspections_http(
                    &self.client,
                    node_inspector_namespace,
                    access.port,
                    access.timeout_secs,
                    progress_range,
                    sink,
                    node_inspector_label,
                )
                .await;
                match collected {
                    Ok(list) if list.is_empty() => {
                        let msg = format!(
                            "ℹ️  未找到节点巡检 Pod（标签 '{}'，命名空间 '{}'），跳过节点巡检。",
                            node_inspector_label, node_inspector_namespace
                        );
                        log(sink, msg);
                        None
                    }
                    Ok(list) => Some(list),
                    Err(e) => {
                        let msg = format!("⚠️  节点巡检采集失败: {}", e);
                        log(sink, msg);
                        None
                    }
                }
            }
            _ => None,
        };

        // 节点采集阶段结束（成功/失败/无数据均视为完成）：把进度推进到接近完成，
        // 剩余的报告生成/落盘由调用方在结束时置 100%。
        if matches!(inspection_type, InspectionType::All | InspectionType::Nodes) {
            if let Some(s) = sink {
                let end_pct = if matches!(inspection_type, InspectionType::All) {
                    99.0
                } else {
                    97.0
                };
                s.progress(end_pct, 100, 100);
            }
        }

        // Synthetic Node Inspection result: issues for nodes with zombie processes (003).
        if let Some(ref nodes) = &node_inspection_results {
            let zombie_issues: Vec<Issue> = nodes
                .iter()
                .filter(|n| n.zombie_count.map(|c| c > 0).unwrap_or(false))
                .map(|n| {
                    let z = n.zombie_count.unwrap_or(0);
                    Issue {
                        severity: IssueSeverity::Warning,
                        category: "Node".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "Node {} has {} zombie process(es)",
                            "节点 {} 有 {} 个僵尸进程",
                            n.node_name,
                            z
                        ),
                        resource: Some(n.node_name.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Identify parent processes and fix reaping; see 003.",
                                "识别父进程并修复回收机制；参见 003。",
                            )
                            .to_string(),
                        rule_id: Some("003".to_string()),
                    }
                })
                .collect();
            if !zombie_issues.is_empty() {
                let check = CheckResult {
                    name: "Node process health".to_string(),
                    description: self
                        .lang
                        .t("Zombie processes on nodes", "节点上的僵尸进程")
                        .to_string(),
                    status: CheckStatus::Warning,
                    score: 0.0,
                    max_score: 100.0,
                    details: Some(crate::lang_fmt!(
                        self.lang,
                        "{} node(s) with zombie processes",
                        "{} 个节点存在僵尸进程",
                        zombie_issues.len()
                    )),
                    recommendations: vec![self
                        .lang
                        .t(
                            "See 003 and fix parent process reaping.",
                            "参见 003 并修复父进程回收。",
                        )
                        .to_string()],
                };
                let summary = InspectionSummary {
                    total_checks: 1,
                    passed_checks: 0,
                    warning_checks: zombie_issues.len() as u32,
                    critical_checks: 0,
                    error_checks: 0,
                    issues: zombie_issues,
                };
                inspections.push(InspectionResult {
                    inspection_type: "Node Inspection".to_string(),
                    timestamp: Utc::now(),
                    overall_score: 0.0,
                    checks: vec![check],
                    summary,
                    certificate_expiries: None,
                    pod_container_states: None,
                    namespace_summary_rows: None,
                });
                overall_score = self.calculate_overall_score(&inspections);
                executive_summary = self.generate_executive_summary(&inspections, overall_score);
            }
        }

        let (display_timestamp, display_timestamp_filename) = node_inspection_results
            .as_ref()
            .and_then(|nodes| nodes.first())
            .and_then(|n| n.timestamp_local.as_ref())
            .and_then(|s| {
                chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%z")
                    .ok()
                    .map(|dt| {
                        (
                            dt.format("%Y-%m-%d %H:%M:%S %:z").to_string(),
                            dt.format("%Y-%m-%d-%H%M%S").to_string(),
                        )
                    })
            })
            .map(|(h, f)| (Some(h), Some(f)))
            .unwrap_or((None, None));

        Ok(ClusterReport {
            cluster_name,
            report_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            overall_score,
            inspections,
            executive_summary,
            cluster_overview,
            node_inspection_results,
            recent_events,
            db_middleware,
            display_timestamp,
            display_timestamp_filename,
        })
    }

    /// Detect database middleware pods by container image keywords.
    async fn collect_db_middleware(&self) -> Result<Vec<DbMiddlewareRow>> {
        const DB_MIDDLEWARE_KEYWORDS: [&str; 13] = [
            "mongodb",
            "mysql",
            "mariadb",
            "etcd",
            "minio",
            "kafka",
            "emqx",
            "redis",
            "rocketmq",
            "postgres",
            "clickhouse",
            "doris",
            "rustfs",
        ];
        let pods_api = self.client.pods(None);
        let pods = pods_api.list(&ListParams::default()).await?;
        let mut out = Vec::new();
        for pod in &pods.items {
            let Some(spec) = &pod.spec else {
                continue;
            };
            let namespace = pod
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let pod_name = pod
                .metadata
                .name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let matched = spec.containers.iter().find(|c| {
                c.image
                    .as_deref()
                    .map(|img| {
                        let lower = img.to_lowercase();
                        DB_MIDDLEWARE_KEYWORDS.iter().any(|k| lower.contains(k))
                    })
                    .unwrap_or(false)
            });
            let Some(matched_container) = matched else {
                continue;
            };
            let image = matched_container.image.clone().unwrap_or_default();
            let ready = pod
                .status
                .as_ref()
                .and_then(|s| s.container_statuses.as_deref())
                .map(|cs| cs.iter().all(|c| c.ready))
                .unwrap_or(false);
            let restart_count = pod
                .status
                .as_ref()
                .map(|s| {
                    let main: u32 = s
                        .container_statuses
                        .as_deref()
                        .map(|cs| cs.iter().map(|c| c.restart_count).sum::<i32>() as u32)
                        .unwrap_or(0);
                    let init: u32 = s
                        .init_container_statuses
                        .as_deref()
                        .map(|cs| cs.iter().map(|c| c.restart_count).sum::<i32>() as u32)
                        .unwrap_or(0);
                    main + init
                })
                .unwrap_or(0);
            out.push(DbMiddlewareRow {
                namespace,
                pod_name,
                image,
                ready,
                restart_count,
            });
        }
        out.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then_with(|| a.pod_name.cmp(&b.pod_name))
        });
        Ok(out)
    }

    /// Fetch recent cluster events (Warning and Error only; Normal is excluded).
    async fn fetch_recent_events(&self, limit: usize) -> Result<Vec<EventRow>> {
        use k8s_openapi::api::core::v1::Event;
        use kube::Api;

        let ns_api = self.client.namespaces();
        let ns_list = ns_api.list(&ListParams::default()).await?;
        const MAX_NAMESPACES: usize = 20;
        let ns_names: Vec<String> = ns_list
            .items
            .into_iter()
            .filter_map(|n| n.metadata.name)
            .take(MAX_NAMESPACES)
            .collect();

        let mut rows: Vec<EventRow> = Vec::new();
        for ns in &ns_names {
            let events_api: Api<Event> = Api::namespaced(self.client.client().clone(), ns);
            let list_params = ListParams::default();
            let events = match events_api.list(&list_params).await {
                Ok(l) => l,
                Err(_) => continue,
            };
            for ev in events.items {
                let type_ = ev.type_.as_deref().unwrap_or("");
                if type_ != "Warning" && type_ != "Error" {
                    continue;
                }
                let namespace = ev.metadata.namespace.as_deref().unwrap_or("").to_string();
                let obj = &ev.involved_object;
                let kind = obj.kind.as_deref().unwrap_or("").to_string();
                let name = obj.name.as_deref().unwrap_or("").to_string();
                let object_ref = if kind.is_empty() || name.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", kind, name)
                };
                let last_seen = ev
                    .last_timestamp
                    .as_ref()
                    .or(ev.first_timestamp.as_ref())
                    .map(|t| t.0.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".to_string());
                let message = ev.message.as_deref().unwrap_or("").to_string();
                let message_trunc = if message.len() > 80 {
                    format!("{}...", &message[..77])
                } else {
                    message
                };
                rows.push(EventRow {
                    namespace,
                    object_ref,
                    event_type: type_.to_string(),
                    reason: ev.reason.as_deref().unwrap_or("").to_string(),
                    message: message_trunc,
                    last_seen,
                });
            }
        }
        rows.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        rows.truncate(limit);
        Ok(rows)
    }

    /// Build cluster overview from node list (and optional server version). Used for report header.
    async fn fetch_cluster_overview(&self) -> Result<ClusterOverview> {
        let nodes_api = self.client.nodes();
        let nodes = nodes_api.list(&ListParams::default()).await?;
        let pods_api = self.client.pods(None);
        let pods = pods_api.list(&ListParams::default()).await?;
        let mut pods_per_node: HashMap<String, u32> = HashMap::new();
        for pod in &pods.items {
            if let Some(ref name) = pod.spec.as_ref().and_then(|s| s.node_name.as_ref()) {
                *pods_per_node.entry(name.to_string()).or_insert(0) += 1;
            }
        }
        let pod_count = pods.items.len() as u32;

        // Pod phase breakdown from existing pods list.
        let mut pod_phase = PodPhaseBreakdown::default();
        for pod in &pods.items {
            let phase = pod
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("Unknown");
            match phase {
                "Running" => pod_phase.running += 1,
                "Pending" => pod_phase.pending += 1,
                "Succeeded" => pod_phase.succeeded += 1,
                "Failed" => pod_phase.failed += 1,
                _ => pod_phase.unknown += 1,
            }
        }

        // Namespace count.
        let ns_api = self.client.namespaces();
        let ns_list = ns_api.list(&ListParams::default()).await?;
        let namespace_count = ns_list.items.len() as u32;

        // Workload summary: Deployments, StatefulSets, DaemonSets (cluster-wide).
        let mut workload = WorkloadSummary::default();
        let dep_api = self.client.deployments(None);
        if let Ok(list) = dep_api.list(&ListParams::default()).await {
            workload.deployments_total = list.items.len() as u32;
            for d in &list.items {
                let desired = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1) as u32;
                let ready = d
                    .status
                    .as_ref()
                    .and_then(|s| s.ready_replicas)
                    .unwrap_or(0) as u32;
                if desired > 0 && ready >= desired {
                    workload.deployments_ready += 1;
                }
            }
        }
        let sts_api = self.client.stateful_sets(None);
        if let Ok(list) = sts_api.list(&ListParams::default()).await {
            workload.statefulsets_total = list.items.len() as u32;
            for s in &list.items {
                let desired = s.spec.as_ref().and_then(|sp| sp.replicas).unwrap_or(1) as u32;
                let ready = s
                    .status
                    .as_ref()
                    .and_then(|st| st.ready_replicas)
                    .unwrap_or(0) as u32;
                if desired > 0 && ready >= desired {
                    workload.statefulsets_ready += 1;
                }
            }
        }
        let ds_api = self.client.daemon_sets(None);
        if let Ok(list) = ds_api.list(&ListParams::default()).await {
            workload.daemonsets_total = list.items.len() as u32;
            for d in &list.items {
                let desired = d
                    .status
                    .as_ref()
                    .map(|s| s.desired_number_scheduled)
                    .unwrap_or(0) as u32;
                let ready = d.status.as_ref().map(|s| s.number_ready).unwrap_or(0) as u32;
                if desired > 0 && ready >= desired {
                    workload.daemonsets_ready += 1;
                }
            }
        }

        // Storage summary: PV, PVC (all ns), StorageClass.
        let mut storage = StorageSummary::default();
        let pv_api = self.client.persistent_volumes();
        if let Ok(list) = pv_api.list(&ListParams::default()).await {
            storage.pv_total = list.items.len() as u32;
        }
        let pvc_api = self.client.persistent_volume_claims(None);
        if let Ok(list) = pvc_api.list(&ListParams::default()).await {
            storage.pvc_total = list.items.len() as u32;
            for pvc in &list.items {
                let phase = pvc
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.as_deref())
                    .unwrap_or("");
                if phase == "Bound" {
                    storage.pvc_bound += 1;
                }
            }
        }
        let sc_api = self.client.storage_classes();
        if let Ok(list) = sc_api.list(&ListParams::default()).await {
            storage.storage_class_count = list.items.len() as u32;
            storage.has_default_storage_class = list.items.iter().any(|sc| {
                sc.metadata
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("storageclass.kubernetes.io/is-default-class"))
                    .map(|v| v.as_str())
                    == Some("true")
            });
        }

        let total = nodes.items.len() as u32;
        let mut ready = 0u32;
        let mut os_arch: HashMap<(String, String), u32> = HashMap::new();
        let mut kubelet_versions: Vec<String> = Vec::new();
        let mut cap_cpu_millis: i64 = 0;
        let mut cap_mem_bytes: i64 = 0;
        let mut alloc_cpu_millis: i64 = 0;
        let mut alloc_mem_bytes: i64 = 0;
        let mut node_list: Vec<NodeRow> = Vec::new();
        let mut node_conditions: Vec<NodeConditionsRow> = Vec::new();
        let mut allocatable_per_node: HashMap<String, (i64, i64, i64)> = HashMap::new();

        const CONDITION_TYPES: &[&str] =
            &["Ready", "MemoryPressure", "DiskPressure", "PIDPressure"];

        for node in &nodes.items {
            let name = node.metadata.name.as_deref().unwrap_or("").to_string();
            let mut os = "Unknown".to_string();
            let mut arch = "unknown".to_string();
            let mut kubelet_version = String::new();
            let mut os_image: Option<String> = None;
            let mut kernel_version: Option<String> = None;
            let mut container_runtime_version: Option<String> = None;
            let mut is_ready = false;
            let mut cond_map: HashMap<String, String> = CONDITION_TYPES
                .iter()
                .map(|&t| (t.to_string(), "Unknown".to_string()))
                .collect();

            if let Some(status) = &node.status {
                if let Some(conditions) = &status.conditions {
                    for c in conditions {
                        if CONDITION_TYPES.contains(&c.type_.as_str()) {
                            cond_map.insert(c.type_.clone(), c.status.clone());
                        }
                        if c.type_ == "Ready" && c.status == "True" {
                            ready += 1;
                            is_ready = true;
                        }
                    }
                }
                if let Some(ref info) = status.node_info {
                    os = info.operating_system.clone();
                    arch = info.architecture.clone();
                    kubelet_version = info.kubelet_version.clone();
                    if !info.os_image.is_empty() {
                        os_image = Some(info.os_image.clone());
                    }
                    if !info.kernel_version.is_empty() {
                        kernel_version = Some(info.kernel_version.clone());
                    }
                    if !info.container_runtime_version.is_empty() {
                        container_runtime_version = Some(info.container_runtime_version.clone());
                    }
                    if !kubelet_version.is_empty() {
                        kubelet_versions.push(kubelet_version.clone());
                    }
                    *os_arch.entry((os.clone(), arch.clone())).or_insert(0) += 1;
                }
                if let (Some(cap), Some(alloc)) = (&status.capacity, &status.allocatable) {
                    let ac = parse_cpu_quantity(alloc.get("cpu")).unwrap_or(0);
                    let am = parse_memory_quantity(alloc.get("memory")).unwrap_or(0);
                    let disk_bytes =
                        parse_memory_quantity(alloc.get("ephemeral-storage")).unwrap_or(0);
                    allocatable_per_node.insert(name.clone(), (ac, am, disk_bytes));
                    cap_cpu_millis += parse_cpu_quantity(cap.get("cpu")).unwrap_or(0);
                    cap_mem_bytes += parse_memory_quantity(cap.get("memory")).unwrap_or(0);
                    alloc_cpu_millis += parse_cpu_quantity(alloc.get("cpu")).unwrap_or(0);
                    alloc_mem_bytes += parse_memory_quantity(alloc.get("memory")).unwrap_or(0);
                }
            }

            let node_pod_count = pods_per_node.get(&name).copied().unwrap_or(0);
            let node_address = node
                .status
                .as_ref()
                .and_then(|s| s.addresses.as_ref())
                .and_then(|addrs| {
                    addrs
                        .iter()
                        .find(|a| a.type_.as_str() == "InternalIP")
                        .map(|a| a.address.clone())
                });
            node_list.push(NodeRow {
                name: name.clone(),
                operating_system: os,
                architecture: arch,
                kubelet_version,
                ready: is_ready,
                pod_count: node_pod_count,
                node_address,
                os_image,
                kernel_version,
                container_runtime_version,
            });
            node_conditions.push(NodeConditionsRow {
                node_name: name,
                ready: cond_map
                    .get("Ready")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string()),
                memory_pressure: cond_map
                    .get("MemoryPressure")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string()),
                disk_pressure: cond_map
                    .get("DiskPressure")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string()),
                pid_pressure: cond_map
                    .get("PIDPressure")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string()),
            });
        }

        kubelet_versions.sort();
        kubelet_versions.dedup();

        let node_summary = if os_arch.is_empty() {
            None
        } else {
            let parts: Vec<String> = os_arch
                .into_iter()
                .map(|((os, arch), count)| {
                    crate::lang_fmt!(
                        self.lang,
                        "{} {} node(s) {}",
                        "{} {} 个节点 {}",
                        os,
                        count,
                        arch
                    )
                })
                .collect();
            let mut summary = parts.join(self.lang.t(", ", "，"));
            if let Some(kv) = kubelet_versions.first() {
                if kubelet_versions.len() == 1 {
                    summary.push_str(&crate::lang_fmt!(
                        self.lang,
                        ", kubelet {}",
                        "，kubelet {}",
                        kv
                    ));
                } else {
                    summary.push_str(&crate::lang_fmt!(
                        self.lang,
                        ", kubelet {}..{}",
                        "，kubelet {}..{}",
                        kv,
                        kubelet_versions.last().unwrap_or(&String::new())
                    ));
                }
            }
            Some(summary)
        };

        const GIB_BYTES: f64 = 1024.0 * 1024.0 * 1024.0;
        let alloc_disk_gi = allocatable_per_node
            .values()
            .map(|&(_c, _m, disk_bytes)| disk_bytes as f64 / GIB_BYTES)
            .sum::<f64>();
        let allocatable_disk_gi = if alloc_disk_gi > 0.0 {
            Some(alloc_disk_gi)
        } else {
            None
        };

        let node_resources = if total > 0 && (cap_cpu_millis > 0 || cap_mem_bytes > 0) {
            Some(NodeResourceSummary {
                capacity_cpu: format_cpu_millis(cap_cpu_millis),
                capacity_memory: format_memory_bytes(cap_mem_bytes),
                allocatable_cpu: format_cpu_millis(alloc_cpu_millis),
                allocatable_memory: format_memory_bytes(alloc_mem_bytes),
                allocatable_disk_gi,
            })
        } else {
            None
        };

        let cluster_version = self.client.server_version().await.ok().flatten();

        let cluster_age_days: Option<u64> = nodes
            .items
            .iter()
            .filter_map(|n| n.metadata.creation_timestamp.as_ref())
            .min()
            .map(|t| {
                let now = Utc::now();
                let creation = t.0;
                (now.signed_duration_since(creation).num_days()).max(0) as u64
            });

        let (metrics_available, node_usage, total_usage_cpu_cores, total_usage_memory_gi) =
            match self.client.node_metrics().await.ok().flatten() {
                Some(metrics) => {
                    let mut rows: Vec<NodeUsageRow> = Vec::new();
                    let mut sum_cpu_millis: i64 = 0;
                    let mut sum_mem_bytes: i64 = 0;
                    for (node_name, cpu_str, mem_str) in metrics {
                        let cpu_millis = parse_cpu_str(&cpu_str).unwrap_or(0);
                        let mem_bytes = parse_memory_str(&mem_str).unwrap_or(0);
                        sum_cpu_millis += cpu_millis;
                        sum_mem_bytes += mem_bytes;
                        let (
                            alloc_cpu_cores,
                            alloc_mem_gi,
                            disk_allocatable_gi,
                            cpu_pct,
                            memory_pct,
                        ) = allocatable_per_node
                            .get(&node_name)
                            .map(|&(alloc_cpu, alloc_mem, disk_bytes)| {
                                let cpu_pct = if alloc_cpu > 0 {
                                    Some((cpu_millis as f64 / alloc_cpu as f64) * 100.0)
                                } else {
                                    None
                                };
                                let memory_pct = if alloc_mem > 0 {
                                    Some((mem_bytes as f64 / alloc_mem as f64) * 100.0)
                                } else {
                                    None
                                };
                                let disk_gi = if disk_bytes > 0 {
                                    Some(disk_bytes as f64 / GIB_BYTES)
                                } else {
                                    None
                                };
                                let cpu_cores = Some(alloc_cpu as f64 / 1000.0);
                                let mem_gi = Some(alloc_mem as f64 / GIB_BYTES);
                                (cpu_cores, mem_gi, disk_gi, cpu_pct, memory_pct)
                            })
                            .unwrap_or((None, None, None, None, None));
                        rows.push(NodeUsageRow {
                            node_name: node_name.clone(),
                            allocatable_cpu_cores: alloc_cpu_cores,
                            cpu_usage: format_cpu_cores(cpu_millis),
                            cpu_pct,
                            allocatable_memory_gi: alloc_mem_gi,
                            memory_usage: format_memory_gi(mem_bytes),
                            memory_pct,
                            disk_allocatable_gi,
                            disk_usage_gi: None,
                            disk_pct: None,
                        });
                    }
                    let total_cpu = if rows.is_empty() {
                        None
                    } else {
                        Some(sum_cpu_millis as f64 / 1000.0)
                    };
                    let total_mem = if rows.is_empty() {
                        None
                    } else {
                        Some(sum_mem_bytes as f64 / GIB_BYTES)
                    };
                    (
                        Some(true),
                        if rows.is_empty() { None } else { Some(rows) },
                        total_cpu,
                        total_mem,
                    )
                }
                None => (Some(false), None, None, None),
            };

        /// Top N containers by high usage (usage/limit >= 80%); only these are shown in the report.
        const CONTAINER_HIGH_USAGE_TOP_N: usize = 20;
        const HIGH_USAGE_PCT: f64 = 0.80;

        let container_usage_notable: Option<Vec<ContainerUsageRow>> = if metrics_available
            != Some(true)
        {
            None
        } else {
            match self.client.pod_metrics().await.ok().flatten() {
                None => None,
                Some(metrics_list) => {
                    let pod_lookup: HashMap<(String, String), &Pod> = pods
                        .items
                        .iter()
                        .filter_map(|p| {
                            let ns = p.metadata.namespace.as_deref().unwrap_or("").to_string();
                            let name = p.metadata.name.as_deref().unwrap_or("").to_string();
                            if name.is_empty() {
                                None
                            } else {
                                Some(((ns, name), p))
                            }
                        })
                        .collect();
                    let mut high_usage_rows: Vec<(f64, ContainerUsageRow)> = Vec::new();
                    for (ns, pod_name, container_name, cpu_str, mem_str) in metrics_list {
                        let cpu_used_m = parse_cpu_str(&cpu_str).unwrap_or(0).max(0) as u64;
                        let mem_used_bytes = parse_memory_str(&mem_str).unwrap_or(0).max(0);
                        let mem_used_mib = (mem_used_bytes / (1024 * 1024)) as u64;

                        let pod = match pod_lookup.get(&(ns.clone(), pod_name.clone())) {
                            Some(p) => p,
                            None => continue,
                        };
                        let spec = match &pod.spec {
                            Some(s) => s,
                            None => continue,
                        };
                        let container = spec.containers.iter().find(|c| c.name == container_name);
                        let container = match container {
                            Some(c) => c,
                            None => continue,
                        };

                        let lim = container.resources.as_ref().and_then(|r| r.limits.as_ref());
                        let cpu_request_m = container
                            .resources
                            .as_ref()
                            .and_then(|r| r.requests.as_ref())
                            .and_then(|r| r.get("cpu"))
                            .and_then(|q| parse_cpu_str(q.0.as_str()))
                            .unwrap_or(0)
                            .max(0) as u64;
                        let mem_request_bytes = container
                            .resources
                            .as_ref()
                            .and_then(|r| r.requests.as_ref())
                            .and_then(|r| r.get("memory"))
                            .and_then(|q| parse_memory_str(q.0.as_str()))
                            .unwrap_or(0)
                            .max(0);
                        let mem_request_mib = (mem_request_bytes / (1024 * 1024)) as u64;
                        let cpu_limit_m = lim
                            .and_then(|r| r.get("cpu"))
                            .and_then(|q| parse_cpu_str(q.0.as_str()))
                            .unwrap_or(0)
                            .max(0) as u64;
                        let mem_limit_bytes = lim
                            .and_then(|r| r.get("memory"))
                            .and_then(|q| parse_memory_str(q.0.as_str()))
                            .unwrap_or(0)
                            .max(0);
                        let mem_limit_mib = (mem_limit_bytes / (1024 * 1024)) as u64;

                        let cpu_pct = if cpu_limit_m > 0 {
                            cpu_used_m as f64 / cpu_limit_m as f64
                        } else {
                            0.0
                        };
                        let mem_pct = if mem_limit_mib > 0 {
                            mem_used_mib as f64 / mem_limit_mib as f64
                        } else {
                            0.0
                        };
                        let high_usage = cpu_pct >= HIGH_USAGE_PCT || mem_pct >= HIGH_USAGE_PCT;
                        if !high_usage {
                            continue;
                        }
                        let sort_score = cpu_pct.max(mem_pct);
                        high_usage_rows.push((
                            sort_score,
                            ContainerUsageRow {
                                namespace: ns,
                                pod_name,
                                container_name,
                                cpu_used_m,
                                cpu_request_m,
                                cpu_limit_m,
                                mem_used_mib,
                                mem_request_mib,
                                mem_limit_mib,
                                notable_reason: "high_usage".to_string(),
                            },
                        ));
                    }
                    high_usage_rows
                        .sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                    let rows: Vec<ContainerUsageRow> = high_usage_rows
                        .into_iter()
                        .map(|(_, r)| r)
                        .take(CONTAINER_HIGH_USAGE_TOP_N)
                        .collect();
                    if rows.is_empty() {
                        None
                    } else {
                        Some(rows)
                    }
                }
            }
        };

        Ok(ClusterOverview {
            cluster_version,
            node_count: total,
            ready_node_count: ready,
            pod_count: Some(pod_count),
            node_summary,
            node_resources,
            node_list: if node_list.is_empty() {
                None
            } else {
                Some(node_list)
            },
            metrics_available,
            node_usage,
            total_usage_cpu_cores,
            total_usage_memory_gi,
            node_conditions: if node_conditions.is_empty() {
                None
            } else {
                Some(node_conditions)
            },
            pod_phase_breakdown: Some(pod_phase),
            namespace_count: Some(namespace_count),
            workload_summary: Some(workload),
            storage_summary: Some(storage),
            cluster_age_days,
            container_usage_notable,
        })
    }

    async fn run_node_inspection(&self) -> Result<InspectionResult> {
        nodes::NodeInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect()
            .await
    }

    async fn run_pod_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        pods::PodInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_resource_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        resources::ResourceInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_network_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        network::NetworkInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_storage_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        storage::StorageInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_security_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        security::SecurityInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_control_plane_inspection(&self) -> Result<InspectionResult> {
        control_plane::ControlPlaneInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect()
            .await
    }

    async fn run_autoscaling_inspection(
        &self,
        namespace: Option<&str>,
    ) -> Result<InspectionResult> {
        autoscaling::AutoscalingInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_batch_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        batch::BatchInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_policy_inspection(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        policies::PoliciesInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_observability_inspection(
        &self,
        namespace: Option<&str>,
    ) -> Result<InspectionResult> {
        observability::ObservabilityInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect(namespace)
            .await
    }

    async fn run_namespace_summary_inspection(&self) -> Result<InspectionResult> {
        namespace_summary::NamespaceSummaryInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect()
            .await
    }

    async fn run_upgrade_readiness_inspection(&self) -> Result<InspectionResult> {
        upgrade::UpgradeInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect()
            .await
    }

    async fn run_certificate_inspection(&self) -> Result<InspectionResult> {
        certificates::CertificateInspector::new(&self.client)
            .with_lang(self.lang)
            .inspect()
            .await
    }

    fn calculate_overall_score(&self, inspections: &[InspectionResult]) -> f64 {
        if inspections.is_empty() {
            return 0.0;
        }

        let total_score: f64 = inspections.iter().map(|i| i.overall_score).sum();
        total_score / inspections.len() as f64
    }

    fn generate_executive_summary(
        &self,
        inspections: &[InspectionResult],
        overall_score: f64,
    ) -> ExecutiveSummary {
        let health_status = match overall_score {
            s if s >= 90.0 => HealthStatus::Excellent,
            s if s >= 80.0 => HealthStatus::Good,
            s if s >= 70.0 => HealthStatus::Fair,
            s if s >= 60.0 => HealthStatus::Poor,
            _ => HealthStatus::Critical,
        };

        let mut key_findings = Vec::new();
        let mut priority_recommendations = Vec::new();
        let mut score_breakdown = HashMap::new();

        for inspection in inspections {
            score_breakdown.insert(inspection.inspection_type.clone(), inspection.overall_score);

            for issue in &inspection.summary.issues {
                if matches!(issue.severity, IssueSeverity::Critical) {
                    key_findings.push(issue.description.clone());
                    priority_recommendations.push(issue.recommendation.clone());
                }
            }
        }

        key_findings.sort();
        key_findings.dedup();
        priority_recommendations.sort();
        priority_recommendations.dedup();

        key_findings.truncate(5);
        priority_recommendations.truncate(5);

        ExecutiveSummary {
            health_status,
            key_findings,
            priority_recommendations,
            score_breakdown,
        }
    }
}
