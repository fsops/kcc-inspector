use anyhow::Result;
use chrono::Utc;
use kube::api::ListParams;
use log::info;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct SecurityInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> SecurityInspector<'a> {
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
        info!("Starting security configuration inspection");

        let mut checks = Vec::new();
        let mut issues = Vec::new();

        // Check RBAC configuration
        self.check_rbac_configuration(&mut checks, &mut issues)
            .await?;

        // Check Pod Security Standards
        self.check_pod_security_standards(namespace, &mut checks, &mut issues)
            .await?;

        // Check Network Policies
        self.check_network_policies(namespace, &mut checks, &mut issues)
            .await?;

        // Check Service Account configuration
        self.check_service_accounts(namespace, &mut checks, &mut issues)
            .await?;

        let overall_score = checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64;

        let summary = self.create_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Security Configuration".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn check_rbac_configuration(
        &self,
        checks: &mut Vec<CheckResult>,
        issues: &mut Vec<Issue>,
    ) -> Result<()> {
        // Check ClusterRoles
        let cluster_roles_api = self.client.cluster_roles();
        let cluster_roles = cluster_roles_api.list(&ListParams::default()).await?;

        let mut dangerous_cluster_roles = 0;
        let total_cluster_roles = cluster_roles.items.len();

        for role in &cluster_roles.items {
            let role_name = role.metadata.name.as_deref().unwrap_or("unknown");

            if let Some(rules) = &role.rules {
                for rule in rules {
                    // Check for overly permissive rules
                    if rule.verbs.contains(&"*".to_string())
                        || rule
                            .resources
                            .as_ref()
                            .is_some_and(|r| r.contains(&"*".to_string()))
                    {
                        dangerous_cluster_roles += 1;

                        if !role_name.starts_with("system:")
                            && !role_name.starts_with("cluster-admin")
                        {
                            issues.push(Issue {
                                severity: IssueSeverity::Warning,
                                category: "ClusterRole".to_string(),
                                description: crate::lang_fmt!(self.lang,
                                        "ClusterRole {} has overly permissive rules",
                                        "ClusterRole {} 具有过于宽松的规则",
                                    role_name
                                ),
                                resource: Some(role_name.to_string()),
                                recommendation: self.lang.t(
                                    "Review and restrict ClusterRole permissions to minimum required",
                                    "审查并将 ClusterRole 权限限制为最小必要权限"
                                ).to_string(),
                                rule_id: Some("501".to_string()),
                            });
                        }
                        break;
                    }
                }
            }
        }

        // Check ClusterRoleBindings
        let cluster_role_bindings_api = self.client.cluster_role_bindings();
        let cluster_role_bindings = cluster_role_bindings_api
            .list(&ListParams::default())
            .await?;

        let mut risky_bindings = 0;
        for binding in &cluster_role_bindings.items {
            let binding_name = binding.metadata.name.as_deref().unwrap_or("unknown");

            let role_ref = &binding.role_ref;
            if role_ref.name == "cluster-admin" {
                if let Some(subjects) = &binding.subjects {
                    for subject in subjects {
                        if subject.kind == "User" && !subject.name.starts_with("system:") {
                            risky_bindings += 1;
                            issues.push(Issue {
                                severity: IssueSeverity::Warning,
                                category: "ClusterRoleBinding".to_string(),
                                description: crate::lang_fmt!(self.lang,
                                        "User {} has cluster-admin privileges",
                                        "用户 {} 具有 cluster-admin 权限",
                                    subject.name
                                ),
                                resource: Some(binding_name.to_string()),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Minimize cluster-admin privileges and use more specific roles",
                                        "最小化 cluster-admin 权限并使用更具体的角色"
                                    )
                                    .to_string(),
                                rule_id: Some("502".to_string()),
                            });
                        }
                        if subject.kind == "ServiceAccount"
                            && subject.namespace.as_deref() != Some("kube-system")
                        {
                            risky_bindings += 1;
                            issues.push(Issue {
                                severity: IssueSeverity::Critical,
                                category: "ClusterRoleBinding".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "ServiceAccount {}/{} has cluster-admin privileges",
                                    "ServiceAccount {}/{} 具有 cluster-admin 权限",
                                    subject.namespace.as_deref().unwrap_or("default"),
                                    subject.name
                                ),
                                resource: Some(binding_name.to_string()),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Review and restrict ServiceAccount permissions",
                                        "审查并限制 ServiceAccount 权限",
                                    )
                                    .to_string(),
                                rule_id: Some("503".to_string()),
                            });
                        }
                    }
                }
            }
        }

        let rbac_score = if total_cluster_roles > 0 {
            ((total_cluster_roles - dangerous_cluster_roles) as f64 / total_cluster_roles as f64)
                * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "RBAC Configuration".to_string(),
            description: self
                .lang
                .t(
                    "Checks for secure RBAC configuration",
                    "检查 RBAC 配置是否安全",
                )
                .to_string(),
            status: if rbac_score >= 90.0 && risky_bindings == 0 {
                CheckStatus::Pass
            } else if rbac_score >= 70.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: if risky_bindings > 0 {
                rbac_score * 0.7
            } else {
                rbac_score
            },
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "Risky roles: {}, Risky bindings: {}",
                "风险角色：{}，风险绑定：{}",
                dangerous_cluster_roles,
                risky_bindings
            )),
            recommendations: if rbac_score < 90.0 || risky_bindings > 0 {
                vec![self
                    .lang
                    .t(
                        "Review and minimize RBAC permissions",
                        "审查并最小化 RBAC 权限",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        Ok(())
    }

    async fn check_pod_security_standards(
        &self,
        namespace: Option<&str>,
        checks: &mut Vec<CheckResult>,
        issues: &mut Vec<Issue>,
    ) -> Result<()> {
        let pods_api = self.client.pods(namespace);
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut total_pods = 0;
        let mut secure_pods = 0;
        let mut pods_running_as_root = 0;
        let mut pods_with_privileged_containers = 0;

        for pod in &pods.items {
            let pod_name = pod.metadata.name.as_deref().unwrap_or("unknown");
            let pod_namespace = pod.metadata.namespace.as_deref().unwrap_or("default");
            let excluded = crate::inspections::is_scoring_excluded_namespace(pod_namespace);
            if !excluded {
                total_pods += 1;
            }

            let mut pod_is_secure = true;

            if let Some(spec) = &pod.spec {
                // Check security context
                if let Some(security_context) = &spec.security_context {
                    if security_context.run_as_user.is_some()
                        && security_context.run_as_user != Some(0)
                    {
                        // Good - not running as root
                    } else if security_context.run_as_user == Some(0) {
                        pods_running_as_root += 1;
                        pod_is_secure = false;
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "Security".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Pod {}/{} runs as root user",
                                "Pod {}/{} 以 root 用户运行",
                                pod_namespace,
                                pod_name
                            ),
                            resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                            recommendation: self
                                .lang
                                .t(
                                    "Configure runAsUser to use non-root user",
                                    "配置 runAsUser 使用非 root 用户",
                                )
                                .to_string(),
                            rule_id: Some("504".to_string()),
                        });
                    }
                } else {
                    // No security context - potentially insecure
                    pod_is_secure = false;
                }

                // Check containers
                for container in &spec.containers {
                    if let Some(security_context) = &container.security_context {
                        if security_context.privileged == Some(true) {
                            pods_with_privileged_containers += 1;
                            pod_is_secure = false;
                            issues.push(Issue {
                                severity: IssueSeverity::Warning,
                                category: "Security".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "Container {} in pod {}/{} runs in privileged mode",
                                    "Pod {}/{} 中的容器 {} 以特权模式运行",
                                    container.name,
                                    pod_namespace,
                                    pod_name
                                ),
                                resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Remove privileged flag unless absolutely necessary",
                                        "除非绝对必要，否则移除 privileged 标志",
                                    )
                                    .to_string(),
                                rule_id: Some("505".to_string()),
                            });
                        }

                        if security_context.run_as_user == Some(0) {
                            pods_running_as_root += 1;
                            pod_is_secure = false;
                            issues.push(Issue {
                                severity: IssueSeverity::Warning,
                                category: "Security".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "Container {} in pod {}/{} runs as root",
                                    "Pod {}/{} 中的容器 {} 以 root 运行",
                                    container.name,
                                    pod_namespace,
                                    pod_name
                                ),
                                resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Configure container to run as non-root user",
                                        "配置容器以非 root 用户运行",
                                    )
                                    .to_string(),
                                rule_id: Some("506".to_string()),
                            });
                        }

                        if security_context.allow_privilege_escalation == Some(true) {
                            pod_is_secure = false;
                            issues.push(Issue {
                                severity: IssueSeverity::Warning,
                                category: "Security".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "Container {} in pod {}/{} allows privilege escalation",
                                    "Pod {}/{} 中的容器 {} 允许权限提升",
                                    container.name,
                                    pod_namespace,
                                    pod_name
                                ),
                                resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Disable allowPrivilegeEscalation",
                                        "禁用 allowPrivilegeEscalation",
                                    )
                                    .to_string(),
                                rule_id: Some("507".to_string()),
                            });
                        }
                    }
                }
            }

            if pod_is_secure && !excluded {
                secure_pods += 1;
            }
        }

        let pod_security_score = if total_pods > 0 {
            (secure_pods as f64 / total_pods as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Pod Security Standards".to_string(),
            description: self
                .lang
                .t(
                    "Checks if pods follow security best practices",
                    "检查 Pod 是否遵循安全最佳实践",
                )
                .to_string(),
            status: if pod_security_score >= 90.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: pod_security_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "Secure pods: {}/{}, Running as root: {}, Privileged: {}",
                "安全 Pod：{}/{}，以 root 运行：{}，特权：{}",
                secure_pods,
                total_pods,
                pods_running_as_root,
                pods_with_privileged_containers
            )),
            recommendations: if pod_security_score < 90.0 {
                vec![self
                    .lang
                    .t(
                        "Configure security contexts for better pod security",
                        "配置安全上下文以增强 Pod 安全性",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        Ok(())
    }

    async fn check_network_policies(
        &self,
        namespace: Option<&str>,
        checks: &mut Vec<CheckResult>,
        issues: &mut Vec<Issue>,
    ) -> Result<()> {
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

        // 未配置任何网络策略时给 60 分（提示但不重罚）
        let coverage_score = if namespaces_with_policies.is_empty() {
            60.0
        } else if total_namespaces > 0 {
            (namespaces_with_policies.len() as f64 / total_namespaces as f64) * 100.0
        } else {
            100.0
        };

        if coverage_score < 50.0 {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "NetworkPolicy".to_string(),
                description: self
                    .lang
                    .t(
                        "Low network policy coverage across namespaces",
                        "各命名空间的网络策略覆盖率较低",
                    )
                    .to_string(),
                resource: Some("cluster".to_string()),
                recommendation: self
                    .lang
                    .t(
                        "Implement network policies for traffic segmentation",
                        "实施网络策略以实现流量隔离",
                    )
                    .to_string(),
                rule_id: Some("508".to_string()),
            });
        }

        checks.push(CheckResult {
            name: "Network Policy Coverage".to_string(),
            description: self
                .lang
                .t(
                    "Checks network policy implementation for traffic segmentation",
                    "检查网络策略实施情况以实现流量隔离",
                )
                .to_string(),
            status: if coverage_score >= 70.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: coverage_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} namespaces with network policies",
                "{}/{} 个命名空间配置了网络策略",
                namespaces_with_policies.len(),
                total_namespaces
            )),
            recommendations: if coverage_score < 70.0 {
                vec![self
                    .lang
                    .t(
                        "Implement network policies for better traffic control",
                        "实施网络策略以实现更好的流量控制",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        Ok(())
    }

    async fn check_service_accounts(
        &self,
        namespace: Option<&str>,
        checks: &mut Vec<CheckResult>,
        issues: &mut Vec<Issue>,
    ) -> Result<()> {
        let pods_api = self.client.pods(namespace);
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut total_pods = 0;
        let mut pods_with_custom_sa = 0;
        let mut _pods_with_default_sa = 0;

        for pod in &pods.items {
            let pod_name = pod.metadata.name.as_deref().unwrap_or("unknown");
            let pod_namespace = pod.metadata.namespace.as_deref().unwrap_or("default");
            let excluded = crate::inspections::is_scoring_excluded_namespace(pod_namespace);
            if !excluded {
                total_pods += 1;
            }

            if let Some(spec) = &pod.spec {
                let service_account = spec.service_account_name.as_deref().unwrap_or("default");

                if service_account == "default" {
                    _pods_with_default_sa += 1;
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "ServiceAccount".to_string(),
                        description: crate::lang_fmt!(self.lang,
                                "Pod {}/{} uses default service account",
                                "Pod {}/{} 使用默认服务账号",
                            pod_namespace, pod_name
                        ),
                        resource: Some(format!("{}/{}", pod_namespace, pod_name)),
                        recommendation: self
                            .lang
                            .t(
                                "Create and use dedicated service accounts with minimal permissions",
                                "创建并使用具有最小权限的专用服务账号"
                            )
                            .to_string(),
                        rule_id: Some("509".to_string()),
                    });
                } else if !excluded {
                    pods_with_custom_sa += 1;
                }
            }
        }

        // 原有规则：得分 = 使用自定义服务账号的 Pod 占比 × 100（占比越高越接近最佳实践）。
        // 最终得分保底：按原规则评分后，若得分 <60 则按 60 分计，≥60 分按实际得分计（score 下限 60）。
        let sa_score = if total_pods > 0 {
            (pods_with_custom_sa as f64 / total_pods as f64) * 100.0
        } else {
            100.0
        };
        // 状态列仍按原有规则判定（原占比 >=80% 为 Pass），仅得分做保底调整
        let final_score = sa_score.max(60.0);

        checks.push(CheckResult {
            name: "Service Account Usage".to_string(),
            description: self
                .lang
                .t(
                    "Checks if pods use dedicated service accounts",
                    "检查 Pod 是否使用专用服务账号",
                )
                .to_string(),
            status: if sa_score >= 80.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score: final_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} pods use custom service accounts",
                "{}/{} 个 Pod 使用自定义服务账号",
                pods_with_custom_sa,
                total_pods
            )),
            recommendations: if sa_score < 80.0 {
                vec![self
                    .lang
                    .t(
                        "Create dedicated service accounts for applications",
                        "为应用创建专用服务账号",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

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
