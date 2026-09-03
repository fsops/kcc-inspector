use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::core::v1::Node;
use kube::Api;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct UpgradeInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> UpgradeInspector<'a> {
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

    pub async fn inspect(&self) -> Result<InspectionResult> {
        let mut checks = Vec::new();
        let mut issues = Vec::new();

        let version_check = self.inspect_versions().await?;
        let deprecated_check = self.inspect_deprecated_api_usage(&mut issues).await?;
        checks.push(version_check);
        checks.push(deprecated_check);

        let overall_score = if checks.is_empty() {
            0.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Upgrade Readiness".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn inspect_versions(&self) -> Result<CheckResult> {
        let nodes_api: Api<Node> = Api::all(self.client.client().clone());
        let nodes = nodes_api.list(&Default::default()).await?;

        if nodes.items.is_empty() {
            return Ok(CheckResult {
                name: "Cluster Version".to_string(),
                description: self
                    .lang
                    .t(
                        "Checks control plane and kubelet versions",
                        "检查控制平面和 kubelet 版本",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 60.0,
                max_score: 100.0,
                details: Some(self.lang.t("No nodes discovered", "未发现节点").to_string()),
                recommendations: vec![self
                    .lang
                    .t(
                        "Ensure kubeconfig has cluster-admin access.",
                        "确保 kubeconfig 具有 cluster-admin 访问权限。",
                    )
                    .to_string()],
            });
        }

        let mut kubelet_versions = Vec::new();
        for node in &nodes.items {
            if let Some(status) = &node.status {
                if let Some(node_info) = &status.node_info {
                    kubelet_versions.push(node_info.kubelet_version.clone());
                }
            }
        }

        kubelet_versions.sort();
        kubelet_versions.dedup();

        let mut recommendations = Vec::new();
        let mut score = 100.0;

        if kubelet_versions.len() > 1 {
            score -= 10.0;
            recommendations.push(
                self.lang
                    .t(
                        "Kubelet versions differ; align node upgrades for consistency.",
                        "kubelet 版本不一致；请统一节点升级以保持一致。",
                    )
                    .to_string(),
            );
        }

        Ok(CheckResult {
            name: "Kubelet Versions".to_string(),
            description: self
                .lang
                .t(
                    "Collects kubelet versions for upgrade planning",
                    "收集 kubelet 版本以规划升级",
                )
                .to_string(),
            status: if score >= 90.0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warning
            },
            score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "Detected kubelet versions: {:?}",
                "检测到的 kubelet 版本：{:?}",
                kubelet_versions
            )),
            recommendations,
        })
    }

    /// Informational check: cluster version and recommendation to audit deprecated APIs.
    /// Typed list only returns current API version; full audit requires raw/discovery API.
    async fn inspect_deprecated_api_usage(&self, _issues: &mut Vec<Issue>) -> Result<CheckResult> {
        let cluster_version = self
            .client
            .server_version()
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());

        let details = crate::lang_fmt!(self.lang,
                "Cluster version: {}. Use kubectl or the official deprecation guide to audit resources for deprecated API versions (e.g. extensions/v1beta1, apps/v1beta1).",
                "集群版本：{}。使用 kubectl 或官方弃用指南审计已弃用或已移除的 API 版本的资源（例如 extensions/v1beta1、apps/v1beta1）。",
            cluster_version
        );

        Ok(CheckResult {
            name: "Deprecated API usage".to_string(),
            description: self
                .lang
                .t(
                    "Reminds to audit resources for deprecated or removed API versions before upgrade",
                    "提醒您在升级前审计已弃用或已移除的 API 版本的资源"
                )
                .to_string(),
            status: CheckStatus::Pass,
            score: 100.0,
            max_score: 100.0,
            details: Some(details),
            recommendations: vec![self.lang.t(
                "Migrate workloads to current API versions before upgrading. See https://kubernetes.io/docs/reference/using-api/deprecation-guide/",
                "升级前将工作负载迁移到当前 API 版本。参见 https://kubernetes.io/docs/reference/using-api/deprecation-guide/"
            ).to_string()],
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
