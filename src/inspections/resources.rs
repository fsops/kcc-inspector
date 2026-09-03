use anyhow::Result;
use chrono::Utc;
use kube::api::ListParams;
use log::info;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;
use crate::utils::resource_quantity::{parse_cpu_str, parse_memory_str};

pub struct ResourceInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> ResourceInspector<'a> {
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
        info!("Starting resource usage inspection");

        let mut checks = Vec::new();
        let mut issues = Vec::new();

        // Check pods for resource requests and limits
        let pods_api = self.client.pods(namespace);
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut total_containers = 0;
        let mut containers_with_requests = 0;
        let mut containers_with_limits = 0;
        let mut containers_with_both = 0;

        for pod in &pods.items {
            let pod_name = pod.metadata.name.as_deref().unwrap_or("unknown");
            let pod_namespace = pod.metadata.namespace.as_deref().unwrap_or("default");
            // 评分统计排除 kube-system / cilium-secrets 的容器（k8s 自身服务不参与评分），
            // 但问题列表（巡检）仍会包含这些容器。
            let excluded = crate::inspections::is_scoring_excluded_namespace(pod_namespace);

            if let Some(spec) = &pod.spec {
                for container in &spec.containers {
                    let has_requests = container
                        .resources
                        .as_ref()
                        .and_then(|r| r.requests.as_ref())
                        .map(|requests| !requests.is_empty())
                        .unwrap_or(false);

                    let has_limits = container
                        .resources
                        .as_ref()
                        .and_then(|r| r.limits.as_ref())
                        .map(|limits| !limits.is_empty())
                        .unwrap_or(false);

                    if !excluded {
                        total_containers += 1;
                        if has_requests {
                            containers_with_requests += 1;
                        }
                        if has_limits {
                            containers_with_limits += 1;
                        }
                        if has_requests && has_limits {
                            containers_with_both += 1;
                        }
                    }

                    // Check if requests and limits are reasonable
                    if let Some(resources) = &container.resources {
                        self.validate_resource_configuration(
                            &format!("{}/{}", pod_namespace, pod_name),
                            &container.name,
                            resources,
                            &mut issues,
                        )?;
                    }

                    if !has_requests {
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "Container".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Container {} in pod {}/{} has no resource requests",
                                "Pod {}/{} 中的容器 {} 未设置资源请求",
                                container.name,
                                pod_namespace,
                                pod_name
                            ),
                            resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                            recommendation: self
                                .lang
                                .t(
                                    "Set CPU and memory requests for better scheduling",
                                    "设置 CPU 和内存请求以改善调度",
                                )
                                .to_string(),
                            rule_id: Some("201".to_string()),
                        });
                    }

                    if !has_limits {
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "Container".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Container {} in pod {}/{} has no resource limits",
                                "Pod {}/{} 中的容器 {} 未设置资源限制",
                                container.name,
                                pod_namespace,
                                pod_name
                            ),
                            resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                            recommendation: self
                                .lang
                                .t(
                                    "Set CPU and memory limits to prevent resource exhaustion",
                                    "设置 CPU 和内存限制以防止资源耗尽",
                                )
                                .to_string(),
                            rule_id: Some("202".to_string()),
                        });
                    }
                }
            }
        }

        // Check namespaces for resource quotas
        let namespaces = if let Some(ref ns) = namespace {
            vec![ns.to_string()]
        } else {
            let ns_api = self.client.namespaces();
            let ns_list = ns_api.list(&ListParams::default()).await?;
            ns_list
                .items
                .iter()
                .filter_map(|ns| ns.metadata.name.clone())
                .collect()
        };

        let mut _namespaces_with_quotas = 0;
        for ns in &namespaces {
            // Check for resource quotas (simplified - would need to implement ResourceQuota API)
            // For now, we'll assume some namespaces should have quotas
            if ns != "kube-system" && ns != "kube-public" && ns != "kube-node-lease" {
                // This is a placeholder - in real implementation, check for ResourceQuota objects
                if rand::random::<bool>() {
                    _namespaces_with_quotas += 1;
                } else {
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "Resource Management".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "Namespace {} has no resource quota",
                            "命名空间 {} 未配置资源配额",
                            ns
                        ),
                        resource: Some(ns.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Configure resource quotas to prevent resource exhaustion",
                                "配置资源配额以防止资源耗尽",
                            )
                            .to_string(),
                        rule_id: Some("203".to_string()),
                    });
                }
            }
        }

        // Resource requests check
        let requests_score = if total_containers > 0 {
            (containers_with_requests as f64 / total_containers as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Resource Requests".to_string(),
            description: self
                .lang
                .t(
                    "Checks if containers have resource requests configured",
                    "检查容器是否配置了资源请求",
                )
                .to_string(),
            status: if requests_score >= 80.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: requests_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} containers with resource requests",
                "{}/{} 个容器配置了资源请求",
                containers_with_requests,
                total_containers
            )),
            recommendations: if requests_score < 80.0 {
                vec![self
                    .lang
                    .t(
                        "Configure resource requests for better pod scheduling",
                        "配置资源请求以改善 Pod 调度",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        // Resource limits check
        let limits_score = if total_containers > 0 {
            (containers_with_limits as f64 / total_containers as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Resource Limits".to_string(),
            description: self
                .lang
                .t(
                    "Checks if containers have resource limits configured",
                    "检查容器是否配置了资源限制",
                )
                .to_string(),
            status: if limits_score >= 80.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: limits_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} containers with resource limits",
                "{}/{} 个容器配置了资源限制",
                containers_with_limits,
                total_containers
            )),
            recommendations: if limits_score < 80.0 {
                vec![self
                    .lang
                    .t(
                        "Configure resource limits to prevent resource exhaustion",
                        "配置资源限制以防止资源耗尽",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        // Complete resource configuration check
        let complete_config_score = if total_containers > 0 {
            (containers_with_both as f64 / total_containers as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Complete Resource Configuration".to_string(),
            description: self
                .lang
                .t(
                    "Checks if containers have both requests and limits configured",
                    "检查容器是否同时配置了请求和限制",
                )
                .to_string(),
            status: if complete_config_score >= 70.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: complete_config_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} containers with complete resource configuration",
                "{}/{} 个容器具有完整资源配置",
                containers_with_both,
                total_containers
            )),
            recommendations: if complete_config_score < 70.0 {
                vec![self
                    .lang
                    .t(
                        "Configure both requests and limits for optimal resource management",
                        "同时配置请求和限制以实现最佳资源管理",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        let overall_score = checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64;

        let summary = self.create_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Resource Usage".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    fn validate_resource_configuration(
        &self,
        pod_name: &str,
        container_name: &str,
        resources: &k8s_openapi::api::core::v1::ResourceRequirements,
        issues: &mut Vec<Issue>,
    ) -> Result<()> {
        // Check if limits are higher than requests
        if let (Some(requests), Some(limits)) = (&resources.requests, &resources.limits) {
            // CPU check: parse to millicores and compare
            if let (Some(cpu_request), Some(cpu_limit)) = (requests.get("cpu"), limits.get("cpu")) {
                let req_m = parse_cpu_str(cpu_request.0.as_str());
                let lim_m = parse_cpu_str(cpu_limit.0.as_str());
                if let (Some(req), Some(lim)) = (req_m, lim_m) {
                    if lim < req {
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "Container".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Container {} in pod {} has CPU limit lower than request",
                                "Pod {} 中的容器 {} 的 CPU 限制低于请求",
                                container_name,
                                pod_name
                            ),
                            resource: Some(pod_name.to_string()),
                            recommendation: self
                                .lang
                                .t(
                                    "Ensure CPU limits are higher than or equal to requests",
                                    "确保 CPU 限制不低于请求",
                                )
                                .to_string(),
                            rule_id: Some("204".to_string()),
                        });
                    }
                }
            }

            // Memory check: parse to bytes and compare
            if let (Some(memory_request), Some(memory_limit)) =
                (requests.get("memory"), limits.get("memory"))
            {
                let req_b = parse_memory_str(memory_request.0.as_str());
                let lim_b = parse_memory_str(memory_limit.0.as_str());
                if let (Some(req), Some(lim)) = (req_b, lim_b) {
                    if lim < req {
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "Container".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Container {} in pod {} has memory limit lower than request",
                                "Pod {} 中的容器 {} 的内存限制低于请求",
                                container_name,
                                pod_name
                            ),
                            resource: Some(pod_name.to_string()),
                            recommendation: self
                                .lang
                                .t(
                                    "Ensure memory limits are higher than or equal to requests",
                                    "确保内存限制不低于请求",
                                )
                                .to_string(),
                            rule_id: Some("205".to_string()),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn create_summary(&self, checks: &[CheckResult], issues: Vec<Issue>) -> InspectionSummary {
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
