use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

const METRICS_SERVER_IDENTIFIERS: [&str; 2] = ["metrics-server", "metricsserver"];
const KUBE_STATE_METRICS_IDENTIFIERS: [&str; 2] = ["kube-state-metrics", "kube_state_metrics"];
const COREDNS_IDENTIFIERS: [&str; 2] = ["coredns", "kube-dns"];
const PROMETHEUS_IDENTIFIERS: [&str; 3] = ["prometheus", "thanos", "victoriametrics"];
const LOGGING_IDENTIFIERS: [&str; 4] = ["fluent", "logstash", "loki", "vector"];
const OPENOBSERVE_IDENTIFIERS: [&str; 2] = ["openobserve", "open-observe"];

pub struct ObservabilityInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> ObservabilityInspector<'a> {
    pub fn new(client: &'a K8sClient) -> Self {
        Self {
            client,
            lang: Lang::default(),
        }
    }

    /// Set the report language for localized data strings (default: Chinese).
    pub fn with_lang(mut self, lang: Lang) -> Self {
        self.lang = lang;
        self
    }

    pub async fn inspect(&self, namespace: Option<&str>) -> Result<InspectionResult> {
        let mut checks = Vec::new();
        let mut issues = Vec::new();

        let metrics_check = self.inspect_metrics_components(&mut issues).await?;
        let coredns_check = self.inspect_coredns(&mut issues).await?;
        let logging_check = self
            .inspect_logging_components(namespace, &mut issues)
            .await?;
        let alerting_check = self
            .inspect_alerting_components(namespace, &mut issues)
            .await?;

        checks.push(metrics_check);
        checks.push(coredns_check);
        checks.push(logging_check);
        checks.push(alerting_check);

        let overall_score = if checks.is_empty() {
            0.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Observability".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn inspect_metrics_components(&self, issues: &mut Vec<Issue>) -> Result<CheckResult> {
        // metrics-server: typically in kube-system
        let pods_api = self.client.pods(Some("kube-system"));
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut metrics_server_found = false;
        let mut kube_state_metrics_found = false;

        for pod in &pods.items {
            if let Some(name) = pod.metadata.name.as_deref() {
                if METRICS_SERVER_IDENTIFIERS
                    .iter()
                    .any(|id| name.contains(id))
                    && is_pod_ready(pod)
                {
                    metrics_server_found = true;
                }
                if KUBE_STATE_METRICS_IDENTIFIERS
                    .iter()
                    .any(|id| name.contains(id))
                    && is_pod_ready(pod)
                {
                    kube_state_metrics_found = true;
                }
            }
        }

        // kube-state-metrics may run in prometheus or monitoring namespace
        if !kube_state_metrics_found {
            for ns in &["prometheus", "monitoring"] {
                let api = self.client.pods(Some(ns));
                if let Ok(list) = api.list(&ListParams::default()).await {
                    for pod in &list.items {
                        if let Some(name) = pod.metadata.name.as_deref() {
                            if KUBE_STATE_METRICS_IDENTIFIERS
                                .iter()
                                .any(|id| name.contains(id))
                                && is_pod_ready(pod)
                            {
                                kube_state_metrics_found = true;
                                break;
                            }
                        }
                    }
                }
                if kube_state_metrics_found {
                    break;
                }
            }
        }

        let mut score: f64 = 100.0;
        let mut recommendations = Vec::new();

        if !metrics_server_found {
            score -= 30.0;
            issues.push(Issue {
                severity: IssueSeverity::Critical,
                category: "Observability".to_string(),
                description: self
                    .lang
                    .t(
                        "metrics-server is missing or not ready",
                        "metrics-server 缺失或未就绪",
                    )
                    .to_string(),
                resource: Some("kube-system".to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Deploy metrics-server to enable HPA and kubectl top commands.",
                        "部署 metrics-server 以启用 HPA 和 kubectl top 命令。",
                    )
                    .to_string(),
                rule_id: Some("A01".to_string()),
            });
            recommendations.push(
                self.lang
                    .t(
                        "Install metrics-server for core metrics APIs.",
                        "安装 metrics-server 以提供核心指标 API。",
                    )
                    .to_string(),
            );
        }

        if !kube_state_metrics_found {
            score -= 20.0;
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "Observability".to_string(),
                description: self
                    .lang
                    .t(
                        "kube-state-metrics is missing or not ready",
                        "kube-state-metrics 缺失或未就绪",
                    )
                    .to_string(),
                resource: Some("kube-system".to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Deploy kube-state-metrics to expose Kubernetes object metrics.",
                        "部署 kube-state-metrics 以暴露 Kubernetes 对象指标。",
                    )
                    .to_string(),
                rule_id: Some("A02".to_string()),
            });
            recommendations.push(
                self.lang
                    .t(
                        "Install kube-state-metrics for Prometheus scraping.",
                        "安装 kube-state-metrics 供 Prometheus 采集。",
                    )
                    .to_string(),
            );
        }

        let status = if score >= 90.0 {
            CheckStatus::Pass
        } else if score >= 60.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "Metrics Pipeline".to_string(),
            description: self
                .lang
                .t(
                    "Checks metrics-server and kube-state-metrics availability",
                    "检查 metrics-server 和 kube-state-metrics 的可用性",
                )
                .to_string(),
            status,
            score: score.max(0.0),
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "metrics-server: {}, kube-state-metrics: {}",
                "metrics-server：{}，kube-state-metrics：{}",
                if metrics_server_found {
                    self.lang.t("present", "存在")
                } else {
                    self.lang.t("missing", "缺失")
                },
                if kube_state_metrics_found {
                    self.lang.t("present", "存在")
                } else {
                    self.lang.t("missing", "缺失")
                }
            )),
            recommendations,
        })
    }

    async fn inspect_coredns(&self, issues: &mut Vec<Issue>) -> Result<CheckResult> {
        let pods_api = self.client.pods(Some("kube-system"));
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut ready = 0u32;
        let mut total = 0u32;
        for pod in &pods.items {
            if let Some(name) = pod.metadata.name.as_deref() {
                if COREDNS_IDENTIFIERS.iter().any(|id| name.contains(id)) {
                    total += 1;
                    if is_pod_ready(pod) {
                        ready += 1;
                    }
                }
            }
        }

        let (status, score, details) = if total == 0 {
            issues.push(Issue {
                severity: IssueSeverity::Critical,
                category: "Observability".to_string(),
                description: self
                    .lang
                    .t(
                        "CoreDNS (cluster DNS) not found in kube-system",
                        "在 kube-system 中未找到 CoreDNS（集群 DNS）",
                    )
                    .to_string(),
                resource: Some("kube-system".to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Ensure CoreDNS or kube-dns is deployed for cluster DNS.",
                        "确保为集群 DNS 部署了 CoreDNS 或 kube-dns。",
                    )
                    .to_string(),
                rule_id: Some("305".to_string()),
            });
            (
                CheckStatus::Critical,
                0.0,
                self.lang
                    .t("CoreDNS: not found", "CoreDNS：未找到")
                    .to_string(),
            )
        } else if ready < total {
            (
                CheckStatus::Warning,
                (ready as f64 / total as f64) * 100.0,
                crate::lang_fmt!(
                    self.lang,
                    "CoreDNS: {}/{} ready",
                    "CoreDNS：{}/{} 就绪",
                    ready,
                    total
                ),
            )
        } else {
            (
                CheckStatus::Pass,
                100.0,
                crate::lang_fmt!(
                    self.lang,
                    "CoreDNS: {}/{} ready",
                    "CoreDNS：{}/{} 就绪",
                    ready,
                    total
                ),
            )
        };

        Ok(CheckResult {
            name: "Cluster DNS (CoreDNS)".to_string(),
            description: self
                .lang
                .t(
                    "Checks CoreDNS/kube-dns availability in kube-system",
                    "检查 kube-system 中 CoreDNS/kube-dns 的可用性",
                )
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(details),
            recommendations: vec![],
        })
    }

    async fn inspect_logging_components(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let target_ns = namespace.unwrap_or("kube-system");
        let pods_api = self.client.pods(Some(target_ns));
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut logging_found = false;
        let mut openobserve_found = false;
        for pod in &pods.items {
            if let Some(name) = pod.metadata.name.as_deref() {
                if LOGGING_IDENTIFIERS.iter().any(|id| name.contains(id)) && is_pod_ready(pod) {
                    logging_found = true;
                    break;
                }
                if OPENOBSERVE_IDENTIFIERS.iter().any(|id| name.contains(id)) && is_pod_ready(pod) {
                    logging_found = true;
                    openobserve_found = true;
                    break;
                }
            }
        }
        // OpenObserve 常部署在其它命名空间，追加探测几个常见位置
        if !logging_found {
            for ns in &["observability", "monitoring", "openobserve"] {
                let api = self.client.pods(Some(ns));
                if let Ok(list) = api.list(&ListParams::default()).await {
                    for pod in &list.items {
                        if let Some(name) = pod.metadata.name.as_deref() {
                            if OPENOBSERVE_IDENTIFIERS.iter().any(|id| name.contains(id))
                                && is_pod_ready(pod)
                            {
                                logging_found = true;
                                openobserve_found = true;
                                break;
                            }
                        }
                    }
                }
                if logging_found {
                    break;
                }
            }
        }

        if logging_found {
            let details = if openobserve_found {
                self.lang
                    .t(
                        "OpenObserve detected (logs ingestion)",
                        "检测到 OpenObserve（日志采集）",
                    )
                    .to_string()
            } else {
                crate::lang_fmt!(
                    self.lang,
                    "Logging components detected in namespace {}",
                    "在命名空间 {} 中检测到日志组件",
                    target_ns
                )
            };
            Ok(CheckResult {
                name: "Logging Stack".to_string(),
                description: self
                    .lang
                    .t(
                        "Checks whether logging collectors are running",
                        "检查日志采集器是否正在运行",
                    )
                    .to_string(),
                status: CheckStatus::Pass,
                score: 100.0,
                max_score: 100.0,
                details: Some(details),
                recommendations: vec![],
            })
        } else {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "Observability".to_string(),
                description: self
                    .lang
                    .t("No logging collector pods detected", "未检测到日志采集 Pod")
                    .to_string(),
                resource: Some(target_ns.to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Deploy Fluentd/Vector/Logstash to aggregate cluster logs.",
                        "部署 Fluentd/Vector/Logstash 以聚合集群日志。",
                    )
                    .to_string(),
                rule_id: Some("A03".to_string()),
            });
            Ok(CheckResult {
                name: "Logging Stack".to_string(),
                description: self
                    .lang
                    .t(
                        "Checks whether logging collectors are running",
                        "检查日志采集器是否正在运行",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 90.0,
                max_score: 100.0,
                details: Some(
                    self.lang
                        .t("No logging stack found", "未找到日志栈")
                        .to_string(),
                ),
                recommendations: vec![self
                    .lang
                    .t(
                        "Install a logging stack (e.g., Fluent Bit + Loki).",
                        "安装日志栈（例如 Fluent Bit + Loki）。",
                    )
                    .to_string()],
            })
        }
    }

    async fn inspect_alerting_components(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let potential_namespaces = [
            namespace.unwrap_or("monitoring"),
            "prometheus",
            "observability",
            "openobserve",
            "kube-system",
        ];

        let mut prometheus_found = false;
        let mut openobserve_found = false;
        for ns in &potential_namespaces {
            let pods_api = self.client.pods(Some(ns));
            if let Ok(pods) = pods_api.list(&ListParams::default()).await {
                for pod in pods.items {
                    if let Some(name) = pod.metadata.name.as_deref() {
                        if PROMETHEUS_IDENTIFIERS.iter().any(|id| name.contains(id))
                            && is_pod_ready(&pod)
                        {
                            prometheus_found = true;
                            break;
                        }
                        // OpenObserve 提供指标/日志/追踪，命中则视为监控栈存在
                        if OPENOBSERVE_IDENTIFIERS.iter().any(|id| name.contains(id))
                            && is_pod_ready(&pod)
                        {
                            prometheus_found = true;
                            openobserve_found = true;
                            break;
                        }
                    }
                }
            }
            if prometheus_found {
                break;
            }
        }

        if prometheus_found {
            Ok(CheckResult {
                name: "Monitoring & Alerting".to_string(),
                description: self
                    .lang
                    .t(
                        "Checks for Prometheus/Thanos/VictoriaMetrics components",
                        "检查 Prometheus/Thanos/VictoriaMetrics 组件",
                    )
                    .to_string(),
                status: CheckStatus::Pass,
                score: 100.0,
                max_score: 100.0,
                details: Some(if openobserve_found {
                    self.lang
                        .t("OpenObserve detected", "检测到 OpenObserve")
                        .to_string()
                } else {
                    self.lang
                        .t(
                            "Prometheus-compatible component detected",
                            "检测到 Prometheus 兼容组件",
                        )
                        .to_string()
                }),
                recommendations: vec![],
            })
        } else {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "Observability".to_string(),
                description: self
                    .lang
                    .t(
                        "No Prometheus-compatible monitoring found",
                        "未找到 Prometheus 兼容的监控",
                    )
                    .to_string(),
                resource: Some("monitoring".to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Deploy Prometheus/Thanos or integrate with managed monitoring.",
                        "部署 Prometheus/Thanos 或集成托管监控。",
                    )
                    .to_string(),
                rule_id: Some("A04".to_string()),
            });
            Ok(CheckResult {
                name: "Monitoring & Alerting".to_string(),
                description: self
                    .lang
                    .t("Checks for monitoring stacks", "检查监控栈")
                    .to_string(),
                status: CheckStatus::Warning,
                score: 90.0,
                max_score: 100.0,
                details: Some(
                    self.lang
                        .t(
                            "No Prometheus-compatible monitoring detected",
                            "未检测到 Prometheus 兼容监控",
                        )
                        .to_string(),
                ),
                recommendations: vec![self
                    .lang
                    .t(
                        "Install Prometheus and Alertmanager for proactive monitoring.",
                        "安装 Prometheus 和 Alertmanager 以进行主动监控。",
                    )
                    .to_string()],
            })
        }
    }

    fn build_summary(&self, checks: &[CheckResult], issues: Vec<Issue>) -> InspectionSummary {
        let total_checks = checks.len() as u32;
        let mut passed_checks = 0;
        let mut warning_checks = 0;
        let mut critical_checks = 0;
        let mut error_checks = 0;

        for check in checks {
            match check.status {
                CheckStatus::Pass => passed_checks += 1,
                CheckStatus::Warning => warning_checks += 1,
                CheckStatus::Critical => critical_checks += 1,
                CheckStatus::Error => error_checks += 1,
            }
        }

        InspectionSummary {
            total_checks,
            passed_checks,
            warning_checks,
            critical_checks,
            error_checks,
            issues,
        }
    }
}

fn is_pod_ready(pod: &Pod) -> bool {
    if let Some(status) = &pod.status {
        if status.phase.as_deref() == Some("Running") {
            if let Some(container_statuses) = &status.container_statuses {
                return container_statuses.iter().all(|c| c.ready);
            }
            return true;
        }
    }
    false
}
