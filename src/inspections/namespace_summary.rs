use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::core::v1::{LimitRange, ResourceQuota};
use kube::api::ListParams;
use kube::Api;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct NamespaceSummaryInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> NamespaceSummaryInspector<'a> {
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
        let rows = self.collect_namespace_summary().await?;
        let check = CheckResult {
            name: "Namespace summary".to_string(),
            description: self
                .lang
                .t(
                    "Per-namespace resource and policy coverage",
                    "按命名空间的资源和策略覆盖率",
                )
                .to_string(),
            status: CheckStatus::Pass,
            score: 100.0,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{} namespaces",
                "{} 个命名空间",
                rows.len()
            )),
            recommendations: vec![],
        };
        let summary = InspectionSummary {
            total_checks: 1,
            passed_checks: 1,
            warning_checks: 0,
            critical_checks: 0,
            error_checks: 0,
            issues: vec![],
        };
        Ok(InspectionResult {
            inspection_type: "Namespace".to_string(),
            timestamp: Utc::now(),
            overall_score: 100.0,
            checks: vec![check],
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: Some(rows),
        })
    }

    async fn collect_namespace_summary(&self) -> Result<Vec<NamespaceSummaryRow>> {
        let ns_api = self.client.namespaces();
        let ns_list = ns_api.list(&ListParams::default()).await?;
        let mut rows = Vec::new();
        for ns in &ns_list.items {
            let name = ns.metadata.name.as_deref().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let pods_api = self.client.pods(Some(&name));
            let pods = pods_api.list(&ListParams::default()).await?;
            let pod_count = pods.items.len() as u32;

            let deployments_api = self.client.deployments(Some(&name));
            let deployments = deployments_api.list(&ListParams::default()).await?;
            let deployment_count = deployments.items.len() as u32;

            let np_api = self.client.network_policies(Some(&name));
            let nps = np_api.list(&ListParams::default()).await?;
            let has_network_policy = !nps.items.is_empty();

            let rq_api: Api<ResourceQuota> = Api::namespaced(self.client.client().clone(), &name);
            let rqs = rq_api.list(&ListParams::default()).await?;
            let has_resource_quota = !rqs.items.is_empty();

            let lr_api: Api<LimitRange> = Api::namespaced(self.client.client().clone(), &name);
            let lrs = lr_api.list(&ListParams::default()).await?;
            let has_limit_range = !lrs.items.is_empty();

            rows.push(NamespaceSummaryRow {
                name,
                pod_count,
                deployment_count,
                has_network_policy,
                has_resource_quota,
                has_limit_range,
            });
        }
        Ok(rows)
    }
}
