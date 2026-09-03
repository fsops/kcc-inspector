use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::autoscaling::v2::{HPAScalingRules, MetricSpec, MetricTarget};
use kube::api::ListParams;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct AutoscalingInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> AutoscalingInspector<'a> {
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

        let hpa_check = self.inspect_hpas(namespace, &mut issues).await?;
        checks.push(hpa_check);

        let overall_score = if checks.is_empty() {
            0.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Autoscaling".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn inspect_hpas(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let hpa_api = self.client.horizontal_pod_autoscalers(namespace);
        let hpas = hpa_api.list(&ListParams::default()).await?;

        if hpas.items.is_empty() {
            return Ok(CheckResult {
                name: "Horizontal Pod Autoscalers".to_string(),
                description: self
                    .lang
                    .t(
                        "Evaluates health and configuration of HPAs",
                        "评估 HPA 的健康状态和配置",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 70.0,
                max_score: 100.0,
                details: Some(
                    self.lang
                        .t(
                            "No HPAs detected in the target scope",
                            "在目标范围内未检测到 HPA",
                        )
                        .to_string(),
                ),
                recommendations: vec![self
                    .lang
                    .t(
                        "Consider deploying HPAs to improve workload elasticity.",
                        "考虑部署 HPA 以提高工作负载弹性。",
                    )
                    .to_string()],
            });
        }

        let mut healthy = 0usize;
        for hpa in &hpas.items {
            let name = hpa
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            // Validate metrics configuration
            if let Some(spec) = &hpa.spec {
                if spec.min_replicas.unwrap_or(1) == spec.max_replicas {
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "Autoscaling".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "HPA {} has identical min/max replicas",
                            "HPA {} 的 min/max 副本数相同",
                            name
                        ),
                        resource: Some(name.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Set a wider min/max replica range so the HPA can scale.",
                                "设置更宽的 min/max 副本范围，以便 HPA 可以伸缩。",
                            )
                            .to_string(),
                        rule_id: Some("701".to_string()),
                    });
                }

                if let Some(metrics) = &spec.metrics {
                    for metric in metrics {
                        self.validate_metric(metric, &name, issues);
                    }
                } else {
                    issues.push(Issue {
                        severity: IssueSeverity::Critical,
                        category: "Autoscaling".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "HPA {} has no metrics configured",
                            "HPA {} 未配置指标",
                            name
                        ),
                        resource: Some(name.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Define CPU/Memory or custom metrics for this HPA.",
                                "为此 HPA 定义 CPU/内存或自定义指标。",
                            )
                            .to_string(),
                        rule_id: Some("702".to_string()),
                    });
                }

                if let Some(behavior) = &spec.behavior {
                    self.validate_behavior(behavior.scale_up.as_ref(), &name, "scale-up", issues);
                    self.validate_behavior(
                        behavior.scale_down.as_ref(),
                        &name,
                        "scale-down",
                        issues,
                    );
                }
            }

            // Evaluate status conditions
            if let Some(status) = &hpa.status {
                if let Some(conditions) = status.conditions.as_ref() {
                    if conditions.iter().all(|c| c.status.as_str() == "True") {
                        healthy += 1;
                    } else {
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "Autoscaling".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "HPA {} reports unhealthy conditions",
                                "HPA {} 报告不健康的条件",
                                name
                            ),
                            resource: Some(name.clone()),
                            recommendation: self
                                .lang
                                .t(
                                    "Check target workload readiness and metrics availability.",
                                    "检查目标工作负载的就绪状态和指标可用性。",
                                )
                                .to_string(),
                            rule_id: Some("703".to_string()),
                        });
                    }
                }
            }
        }

        let score = (healthy as f64 / hpas.items.len() as f64) * 100.0;
        let status = if score >= 90.0 {
            CheckStatus::Pass
        } else if score >= 70.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "Horizontal Pod Autoscalers".to_string(),
            description: self
                .lang
                .t(
                    "Checks configuration and health of HPAs",
                    "检查 HPA 的配置和健康状态",
                )
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} HPAs healthy",
                "{}/{} 个 HPA 健康",
                healthy,
                hpas.items.len()
            )),
            recommendations: if score < 100.0 {
                vec![self.lang.t(
                    "Ensure metrics.k8s.io and custom metric APIs are available, and verify workload readiness.",
                    "确保 metrics.k8s.io 和自定义指标 API 可用，并验证工作负载的就绪状态。"
                ).to_string()]
            } else {
                vec![]
            },
        })
    }

    fn validate_metric(&self, metric: &MetricSpec, name: &str, issues: &mut Vec<Issue>) {
        match metric.type_.as_str() {
            "Resource" => {
                if let Some(resource) = &metric.resource {
                    validate_target(
                        &resource.target,
                        resource.name.as_str(),
                        name,
                        self.lang,
                        issues,
                    );
                }
            }
            "Pods" => {
                if let Some(pods) = &metric.pods {
                    validate_target(
                        &pods.target,
                        pods.metric.name.as_str(),
                        name,
                        self.lang,
                        issues,
                    );
                }
            }
            "Object" => {
                if let Some(object) = &metric.object {
                    validate_target(
                        &object.target,
                        object.metric.name.as_str(),
                        name,
                        self.lang,
                        issues,
                    );
                }
            }
            "External" => {
                if let Some(ext) = &metric.external {
                    validate_target(
                        &ext.target,
                        ext.metric.name.as_str(),
                        name,
                        self.lang,
                        issues,
                    );
                }
            }
            "ContainerResource" => {
                if let Some(container) = &metric.container_resource {
                    validate_target(
                        &container.target,
                        container.name.as_str(),
                        name,
                        self.lang,
                        issues,
                    );
                }
            }
            _ => {}
        }
    }

    fn validate_behavior(
        &self,
        rules: Option<&HPAScalingRules>,
        name: &str,
        direction: &str,
        issues: &mut Vec<Issue>,
    ) {
        if let Some(rules) = rules {
            if let Some(select_policy) = &rules.select_policy {
                if select_policy.as_str() == "Disabled" {
                    let direction_localized = match (self.lang, direction) {
                        (Lang::Zh, "scale-up") => "扩容",
                        (Lang::Zh, "scale-down") => "缩容",
                        _ => direction,
                    };
                    issues.push(Issue {
                        severity: IssueSeverity::Info,
                        category: "Autoscaling".to_string(),
                        description: crate::lang_fmt!(self.lang,
                                "HPA {} has {} behavior disabled",
                                "HPA {} 的 {} 行为已禁用",
                            name, direction_localized
                        ),
                        resource: Some(name.to_string()),
                        recommendation: self.lang.t(
                            "Review HPA behavior policy to ensure scaling is permitted when needed.",
                            "检查 HPA 行为策略，确保在需要时允许伸缩。"
                        ).to_string(),
                        rule_id: Some("704".to_string()),
                    });
                }
            }
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

fn validate_target(
    target: &MetricTarget,
    metric_name: &str,
    hpa: &str,
    lang: Lang,
    issues: &mut Vec<Issue>,
) {
    if target.average_utilization.is_none()
        && target.average_value.is_none()
        && target.value.is_none()
    {
        issues.push(Issue {
            severity: IssueSeverity::Warning,
            category: "Autoscaling".to_string(),
            description: crate::lang_fmt!(
                lang,
                "HPA {} metric {} missing scaling target",
                "HPA {} 的指标 {} 缺少伸缩目标",
                hpa,
                metric_name
            ),
            resource: Some(hpa.to_string()),
            recommendation: lang
                .t(
                    "Configure averageUtilization, averageValue, or value for the metric target.",
                    "为指标目标配置 averageUtilization、averageValue 或 value。",
                )
                .to_string(),
            rule_id: Some("705".to_string()),
        });
    }
}
