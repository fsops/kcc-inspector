use anyhow::Result;
use chrono::Utc;
use kube::api::ListParams;
use log::info;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct NetworkInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> NetworkInspector<'a> {
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
        info!("Starting network connectivity inspection");

        let mut checks = Vec::new();
        let mut issues = Vec::new();

        // Check services
        let services_api = self.client.services(namespace);
        let services = services_api.list(&ListParams::default()).await?;

        let mut total_services = 0;
        let mut services_with_endpoints = 0;
        let mut _headless_services = 0;

        for service in &services.items {
            let service_name = service.metadata.name.as_deref().unwrap_or("unknown");
            let service_namespace = service.metadata.namespace.as_deref().unwrap_or("default");

            total_services += 1;

            if let Some(spec) = &service.spec {
                // Check if service is headless
                if spec.cluster_ip.as_deref() == Some("None") {
                    _headless_services += 1;
                }

                // Check service type and configuration
                match spec.type_.as_deref() {
                    Some("LoadBalancer") => {
                        if let Some(status) = &service.status {
                            if let Some(load_balancer) = &status.load_balancer {
                                if load_balancer.ingress.is_none()
                                    || load_balancer.ingress.as_ref().unwrap().is_empty()
                                {
                                    issues.push(Issue {
                                        severity: IssueSeverity::Warning,
                                        category: "Service".to_string(),
                                        description: crate::lang_fmt!(self.lang,
                                                "LoadBalancer service {}/{} has no external IP assigned",
                                                "LoadBalancer 服务 {}/{} 未分配外部 IP",
                                            service_namespace, service_name
                                        ),
                                        resource: Some(format!("{}/{}", service_namespace, service_name)),
                                        recommendation: self.lang.t(
                                            "Check LoadBalancer configuration and cloud provider settings",
                                            "检查 LoadBalancer 配置和云提供商设置"
                                        ).to_string(),
                                        rule_id: Some("301".to_string()),
                                    });
                                }
                            }
                        }
                    }
                    Some("NodePort") => {
                        if let Some(ports) = &spec.ports {
                            for port in ports {
                                if let Some(node_port) = port.node_port {
                                    if !(30000..=32767).contains(&node_port) {
                                        issues.push(Issue {
                                            severity: IssueSeverity::Info,
                                            category: "Service".to_string(),
                                            description: crate::lang_fmt!(self.lang,
                                                    "Service {}/{} uses NodePort {} outside recommended range",
                                                    "服务 {}/{} 使用的 NodePort {} 超出推荐范围",
                                                service_namespace, service_name, node_port
                                            ),
                                            resource: Some(format!("{}/{}", service_namespace, service_name)),
                                            recommendation: self
                                                .lang
                                                .t(
                                                    "Use NodePort in range 30000-32767",
                                                    "使用 30000-32767 范围内的 NodePort"
                                                )
                                                .to_string(),
                                            rule_id: Some("302".to_string()),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }

                // Check if service has selectors (for endpoint discovery)
                if spec.selector.is_some() && !spec.selector.as_ref().unwrap().is_empty() {
                    services_with_endpoints += 1;
                } else if spec.cluster_ip.as_deref() != Some("None") {
                    // Exclude default/kubernetes (default API server service)
                    if !(service_namespace == "default" && service_name == "kubernetes") {
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "Service".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Service {}/{} has no selector and may not have endpoints",
                                "服务 {}/{} 没有选择器，可能没有端点",
                                service_namespace,
                                service_name
                            ),
                            resource: Some(format!("{}/{}", service_namespace, service_name)),
                            recommendation: self
                                .lang
                                .t(
                                    "Ensure service has proper selectors or manual endpoints",
                                    "确保服务具有正确的选择器或手动端点",
                                )
                                .to_string(),
                            rule_id: Some("303".to_string()),
                        });
                    }
                }
            }
        }

        // Check network policies
        let network_policies_api = self.client.network_policies(namespace);
        let network_policies = network_policies_api.list(&ListParams::default()).await?;

        let namespaces_api = self.client.namespaces();
        let namespaces_list = namespaces_api.list(&ListParams::default()).await?;
        let total_namespaces = namespaces_list.items.len();

        let mut namespaces_with_policies = std::collections::HashSet::new();
        for policy in &network_policies.items {
            if let Some(policy_namespace) = &policy.metadata.namespace {
                namespaces_with_policies.insert(policy_namespace.clone());
            }
        }

        // DNS check (simplified)
        let dns_check = self.check_dns_configuration(&mut issues).await?;

        // Service connectivity check
        let service_score = if total_services > 0 {
            (services_with_endpoints as f64 / total_services as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Service Configuration".to_string(),
            description: self
                .lang
                .t(
                    "Checks if services are properly configured with selectors",
                    "检查服务是否配置了正确的选择器",
                )
                .to_string(),
            status: if service_score >= 90.0 {
                CheckStatus::Pass
            } else if service_score >= 70.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: service_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} services with proper configuration",
                "{}/{} 个服务配置正确",
                services_with_endpoints,
                total_services
            )),
            recommendations: if service_score < 90.0 {
                vec![self
                    .lang
                    .t(
                        "Review service configurations and selectors",
                        "检查服务配置和选择器",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        // Network policy coverage
        let policy_coverage = if total_namespaces > 0 {
            (namespaces_with_policies.len() as f64 / total_namespaces as f64) * 100.0
        } else {
            0.0
        };
        // 未配置任何网络策略时给 60 分（提示但不重罚）
        let policy_score = if namespaces_with_policies.is_empty() {
            60.0
        } else {
            policy_coverage
        };

        checks.push(CheckResult {
            name: "Network Policy Coverage".to_string(),
            description: self
                .lang
                .t(
                    "Checks if namespaces have network policies for security",
                    "检查命名空间是否配置了网络策略以确保安全",
                )
                .to_string(),
            status: if policy_score >= 70.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: policy_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} namespaces with network policies",
                "{}/{} 个命名空间配置了网络策略",
                namespaces_with_policies.len(),
                total_namespaces
            )),
            recommendations: if policy_score < 70.0 {
                vec![self
                    .lang
                    .t(
                        "Implement network policies for better security isolation",
                        "实施网络策略以实现更好的安全隔离",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        // DNS configuration check
        checks.push(CheckResult {
            name: "DNS Configuration".to_string(),
            description: self
                .lang
                .t("Checks DNS service availability", "检查 DNS 服务可用性")
                .to_string(),
            status: if dns_check {
                CheckStatus::Pass
            } else {
                CheckStatus::Critical
            },
            score: if dns_check { 100.0 } else { 0.0 },
            max_score: 100.0,
            details: Some(if dns_check {
                self.lang
                    .t("DNS service is available", "DNS 服务可用")
                    .to_string()
            } else {
                self.lang
                    .t("DNS service issues detected", "检测到 DNS 服务问题")
                    .to_string()
            }),
            recommendations: if !dns_check {
                vec![self
                    .lang
                    .t(
                        "Check CoreDNS or kube-dns deployment",
                        "检查 CoreDNS 或 kube-dns 部署",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        let overall_score = checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64;

        let summary = self.create_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Network Connectivity".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn check_dns_configuration(&self, issues: &mut Vec<Issue>) -> Result<bool> {
        // Check for CoreDNS or kube-dns deployment
        let deployments_api = self.client.deployments(Some("kube-system"));
        let deployments = deployments_api.list(&ListParams::default()).await?;

        let mut has_dns_deployment = false;
        for deployment in &deployments.items {
            if let Some(name) = &deployment.metadata.name {
                if name.contains("coredns") || name.contains("kube-dns") {
                    has_dns_deployment = true;

                    // Check if deployment is ready
                    if let Some(status) = &deployment.status {
                        let ready_replicas = status.ready_replicas.unwrap_or(0);
                        let desired_replicas = status.replicas.unwrap_or(0);

                        if ready_replicas < desired_replicas {
                            issues.push(Issue {
                                severity: IssueSeverity::Critical,
                                category: "Deployment".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "DNS deployment {} has {}/{} replicas ready",
                                    "DNS 部署 {} 有 {}/{} 个副本就绪",
                                    name,
                                    ready_replicas,
                                    desired_replicas
                                ),
                                resource: Some(format!("kube-system/{}", name)),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Check DNS deployment logs and resource availability",
                                        "检查 DNS 部署日志和资源可用性",
                                    )
                                    .to_string(),
                                rule_id: Some("304".to_string()),
                            });
                            return Ok(false);
                        }
                    }
                    break;
                }
            }
        }

        if !has_dns_deployment {
            issues.push(Issue {
                severity: IssueSeverity::Critical,
                category: "Namespace".to_string(),
                description: self
                    .lang
                    .t("No DNS service deployment found", "未找到 DNS 服务部署")
                    .to_string(),
                resource: Some("kube-system".to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Deploy CoreDNS or kube-dns for cluster DNS resolution",
                        "部署 CoreDNS 或 kube-dns 以提供集群 DNS 解析",
                    )
                    .to_string(),
                rule_id: Some("305".to_string()),
            });
            return Ok(false);
        }

        Ok(true)
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
