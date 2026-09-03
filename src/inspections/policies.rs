use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::core::v1::{LimitRange, ResourceQuota};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::ListParams;
use kube::Api;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct PoliciesInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> PoliciesInspector<'a> {
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

        let quota_check = self.inspect_resource_quotas(namespace, &mut issues).await?;
        let limit_check = self.inspect_limit_ranges(namespace, &mut issues).await?;
        let pdb_check = self.inspect_pdbs(namespace, &mut issues).await?;

        checks.push(quota_check);
        checks.push(limit_check);
        checks.push(pdb_check);

        let overall_score = if checks.is_empty() {
            0.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Policy & Governance".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn inspect_resource_quotas(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let quota_api: Api<ResourceQuota> = match namespace {
            Some(ns) => Api::namespaced(self.client.client().clone(), ns),
            None => Api::all(self.client.client().clone()),
        };
        let quotas = quota_api.list(&ListParams::default()).await?;

        if namespace.is_some() {
            if quotas.items.is_empty() {
                issues.push(Issue {
                    severity: IssueSeverity::Warning,
                    category: "Policy".to_string(),
                    description: self
                        .lang
                        .t(
                            "Namespace lacks ResourceQuota",
                            "命名空间缺少 ResourceQuota",
                        )
                        .to_string(),
                    resource: namespace.map(|ns| ns.to_string()),
                    recommendation: self
                        .lang
                        .t(
                            "Define ResourceQuota to prevent resource exhaustion.",
                            "定义 ResourceQuota 以防止资源耗尽。",
                        )
                        .to_string(),
                    rule_id: Some("901".to_string()),
                });
                return Ok(CheckResult {
                    name: "Resource Quotas".to_string(),
                    description: self
                        .lang
                        .t(
                            "Checks namespace-level ResourceQuota presence",
                            "检查命名空间级别的 ResourceQuota 是否存在",
                        )
                        .to_string(),
                    status: CheckStatus::Warning,
                    score: 60.0,
                    max_score: 100.0,
                    details: Some(
                        self.lang
                            .t(
                                "Namespace has no ResourceQuota",
                                "命名空间没有 ResourceQuota",
                            )
                            .to_string(),
                    ),
                    recommendations: vec![self
                        .lang
                        .t(
                            "Create ResourceQuota to enforce resource boundaries.",
                            "创建 ResourceQuota 以强制资源边界。",
                        )
                        .to_string()],
                });
            }
        } else if quotas.items.is_empty() {
            return Ok(CheckResult {
                name: "Resource Quotas".to_string(),
                description: self
                    .lang
                    .t(
                        "Checks cluster-wide ResourceQuota coverage",
                        "检查集群范围的 ResourceQuota 覆盖率",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 60.0,
                max_score: 100.0,
                details: Some(
                    self.lang
                        .t(
                            "No ResourceQuota objects found",
                            "未找到 ResourceQuota 对象",
                        )
                        .to_string(),
                ),
                recommendations: vec![self
                    .lang
                    .t(
                        "Define ResourceQuota in multi-tenant namespaces.",
                        "在多租户命名空间中定义 ResourceQuota。",
                    )
                    .to_string()],
            });
        }

        Ok(CheckResult {
            name: "Resource Quotas".to_string(),
            description: self
                .lang
                .t("Checks namespace quotas", "检查命名空间配额")
                .to_string(),
            status: CheckStatus::Pass,
            score: 100.0,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{} quotas identified",
                "识别到 {} 个配额",
                quotas.items.len()
            )),
            recommendations: vec![],
        })
    }

    async fn inspect_limit_ranges(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let limit_api: Api<LimitRange> = match namespace {
            Some(ns) => Api::namespaced(self.client.client().clone(), ns),
            None => Api::all(self.client.client().clone()),
        };
        let limits = limit_api.list(&ListParams::default()).await?;

        if limits.items.is_empty() {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "Policy".to_string(),
                description: self
                    .lang
                    .t("No LimitRange defined", "未定义 LimitRange")
                    .to_string(),
                resource: Some(
                    namespace
                        .map(|ns| ns.to_string())
                        .unwrap_or_else(|| "cluster".to_string()),
                ),
                recommendation: self
                    .lang
                    .t(
                        "Define LimitRange to ensure pod resource defaults and limits.",
                        "定义 LimitRange 以确保 Pod 资源默认值和限制。",
                    )
                    .to_string(),
                rule_id: Some("902".to_string()),
            });
            return Ok(CheckResult {
                name: "Limit Ranges".to_string(),
                description: self
                    .lang
                    .t(
                        "Ensures namespaces have LimitRange for default resource settings",
                        "确保命名空间具有用于默认资源设置的 LimitRange",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 65.0,
                max_score: 100.0,
                details: Some(
                    self.lang
                        .t("No LimitRange objects found", "未找到 LimitRange 对象")
                        .to_string(),
                ),
                recommendations: vec![self
                    .lang
                    .t(
                        "Create LimitRange to enforce default requests/limits.",
                        "创建 LimitRange 以强制默认请求/限制。",
                    )
                    .to_string()],
            });
        }

        Ok(CheckResult {
            name: "Limit Ranges".to_string(),
            description: self
                .lang
                .t("Checks LimitRange presence", "检查 LimitRange 是否存在")
                .to_string(),
            status: CheckStatus::Pass,
            score: 100.0,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{} LimitRange objects found",
                "找到 {} 个 LimitRange 对象",
                limits.items.len()
            )),
            recommendations: vec![],
        })
    }

    async fn inspect_pdbs(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let pdb_api: Api<PodDisruptionBudget> = match namespace {
            Some(ns) => Api::namespaced(self.client.client().clone(), ns),
            None => Api::all(self.client.client().clone()),
        };
        let pdbs = pdb_api.list(&ListParams::default()).await?;

        if pdbs.items.is_empty() {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "Policy".to_string(),
                description: self
                    .lang
                    .t(
                        "No PodDisruptionBudget configured",
                        "未配置 PodDisruptionBudget"
                    )
                    .to_string(),
                resource: namespace.map(|ns| ns.to_string()),
                recommendation: self.lang.t(
                    "Define PodDisruptionBudget for critical workloads to avoid voluntary eviction impact.",
                    "为关键工作负载定义 PodDisruptionBudget，以避免自愿驱逐的影响。"
                ).to_string(),
                rule_id: Some("903".to_string()),
            });
            return Ok(CheckResult {
                name: "Pod Disruption Budgets".to_string(),
                description: self
                    .lang
                    .t("Checks PDB coverage", "检查 PDB 覆盖率")
                    .to_string(),
                status: CheckStatus::Warning,
                score: 70.0,
                max_score: 100.0,
                details: Some(self.lang.t("No PDBs found", "未找到 PDB").to_string()),
                recommendations: vec![self
                    .lang
                    .t(
                        "Add PDBs for stateful or critical deployments.",
                        "为有状态或关键 Deployment 添加 PDB。",
                    )
                    .to_string()],
            });
        }

        let mut unhealthy = 0usize;
        for pdb in pdbs.items {
            if let Some(status) = pdb.status {
                let disruptions_allowed = status.disruptions_allowed;
                let expected_pods = status.expected_pods;
                if disruptions_allowed == 0 && expected_pods > 1 {
                    unhealthy += 1;
                    let name = pdb.metadata.name.unwrap_or_else(|| "unknown".to_string());
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "Policy".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "PDB {} currently blocks disruptions",
                            "PDB {} 当前阻止中断",
                            name
                        ),
                        resource: Some(name.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Ensure enough replicas to satisfy PDB requirements.",
                                "确保有足够的副本满足 PDB 要求。",
                            )
                            .to_string(),
                        rule_id: Some("904".to_string()),
                    });
                }
            }
        }

        let score = if unhealthy == 0 { 100.0 } else { 80.0 }; // Soft penalty
        let status = if unhealthy == 0 {
            CheckStatus::Pass
        } else {
            CheckStatus::Warning
        };

        Ok(CheckResult {
            name: "Pod Disruption Budgets".to_string(),
            description: self
                .lang
                .t("Evaluates PDB coverage and status", "评估 PDB 覆盖率和状态")
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(if unhealthy == 0 {
                self.lang
                    .t("All PDBs allow disruption", "所有 PDB 都允许中断")
                    .to_string()
            } else {
                crate::lang_fmt!(
                    self.lang,
                    "{} PDBs currently block disruption",
                    "{} 个 PDB 当前阻止中断",
                    unhealthy
                )
            }),
            recommendations: if unhealthy > 0 {
                vec![self
                    .lang
                    .t(
                        "Scale workloads or adjust PDB thresholds to allow controlled disruptions.",
                        "扩展工作负载或调整 PDB 阈值以允许受控中断。",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        })
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
