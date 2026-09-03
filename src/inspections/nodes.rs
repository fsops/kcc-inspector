use anyhow::Result;
use chrono::Utc;
use kube::api::ListParams;
use log::{info, warn};

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct NodeInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> NodeInspector<'a> {
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
        info!("Starting node health inspection");

        let nodes_api = self.client.nodes();
        let nodes = nodes_api.list(&ListParams::default()).await?;

        let mut checks = Vec::new();
        let mut issues = Vec::new();

        let total_nodes = nodes.items.len();
        let mut ready_nodes = 0;
        let mut nodes_with_pressure = 0;

        for node in &nodes.items {
            let node_name = node.metadata.name.as_deref().unwrap_or("unknown");

            // Check node ready status
            if let Some(status) = &node.status {
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        match condition.type_.as_str() {
                            "Ready" => {
                                if condition.status == "True" {
                                    ready_nodes += 1;
                                } else {
                                    issues.push(Issue {
                                        severity: IssueSeverity::Critical,
                                        category: "Node".to_string(),
                                        description: crate::lang_fmt!(
                                            self.lang,
                                            "Node {} is not ready",
                                            "节点 {} 未就绪",
                                            node_name
                                        ),
                                        resource: Some(node_name.to_string()),
                                        recommendation: self
                                            .lang
                                            .t(
                                                "Check node logs and system resources",
                                                "检查节点日志和系统资源",
                                            )
                                            .to_string(),
                                        rule_id: Some("001".to_string()),
                                    });
                                }
                            }
                            "MemoryPressure" | "DiskPressure" | "PIDPressure"
                                if condition.status == "True" =>
                            {
                                nodes_with_pressure += 1;
                                issues.push(Issue {
                                    severity: IssueSeverity::Warning,
                                    category: "Node".to_string(),
                                    description: crate::lang_fmt!(
                                        self.lang,
                                        "Node {} has {}",
                                        "节点 {} 存在 {}",
                                        node_name,
                                        self.lang.condition_type_name(&condition.type_)
                                    ),
                                    resource: Some(node_name.to_string()),
                                    recommendation: crate::lang_fmt!(
                                        self.lang,
                                        "Investigate {} on node",
                                        "调查节点上的 {}",
                                        self.lang.condition_type_name(&condition.type_)
                                    ),
                                    rule_id: Some("002".to_string()),
                                });
                            }
                            _ => {}
                        }
                    }
                }

                // Check node capacity and allocatable resources
                if let (Some(capacity), Some(allocatable)) = (&status.capacity, &status.allocatable)
                {
                    self.check_node_resources(
                        node_name,
                        capacity,
                        allocatable,
                        &mut checks,
                        &mut issues,
                    )?;
                }
            }
        }

        // Node readiness check
        let readiness_score = if total_nodes > 0 {
            (ready_nodes as f64 / total_nodes as f64) * 100.0
        } else {
            0.0
        };

        checks.push(CheckResult {
            name: "Node Readiness".to_string(),
            description: self
                .lang
                .t(
                    "Checks if all nodes are in Ready state",
                    "检查所有节点是否处于就绪状态",
                )
                .to_string(),
            status: if readiness_score >= 100.0 {
                CheckStatus::Pass
            } else if readiness_score >= 80.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: readiness_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} nodes are ready",
                "{}/{} 个节点已就绪",
                ready_nodes,
                total_nodes
            )),
            recommendations: if readiness_score < 100.0 {
                vec![self
                    .lang
                    .t("Investigate non-ready nodes", "调查未就绪的节点")
                    .to_string()]
            } else {
                vec![]
            },
        });

        // Node pressure check
        let pressure_score = if total_nodes > 0 {
            ((total_nodes - nodes_with_pressure) as f64 / total_nodes as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Node Pressure".to_string(),
            description: self
                .lang
                .t(
                    "Checks for memory, disk, or PID pressure on nodes",
                    "检查节点上的内存、磁盘或 PID 压力",
                )
                .to_string(),
            status: if pressure_score >= 100.0 {
                CheckStatus::Pass
            } else if pressure_score >= 80.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: pressure_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} nodes without pressure",
                "{}/{} 个节点无压力",
                total_nodes - nodes_with_pressure,
                total_nodes
            )),
            recommendations: if pressure_score < 100.0 {
                vec![self
                    .lang
                    .t(
                        "Monitor node resource usage and consider scaling",
                        "监控节点资源使用情况并考虑扩容",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        let overall_score = checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64;

        let summary = self.create_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Node Health".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    fn check_node_resources(
        &self,
        node_name: &str,
        capacity: &std::collections::BTreeMap<
            String,
            k8s_openapi::apimachinery::pkg::api::resource::Quantity,
        >,
        allocatable: &std::collections::BTreeMap<
            String,
            k8s_openapi::apimachinery::pkg::api::resource::Quantity,
        >,
        _checks: &mut Vec<CheckResult>,
        _issues: &mut Vec<Issue>,
    ) -> Result<()> {
        // Check CPU allocatable vs capacity
        if let (Some(cpu_capacity), Some(cpu_allocatable)) =
            (capacity.get("cpu"), allocatable.get("cpu"))
        {
            let capacity_str = &cpu_capacity.0;
            let allocatable_str = &cpu_allocatable.0;

            // Simple string comparison for demonstration - in production, you'd parse these properly
            if allocatable_str != capacity_str {
                warn!("Node {} has reserved CPU resources", node_name);
            }
        }

        // Check memory allocatable vs capacity
        if let (Some(memory_capacity), Some(memory_allocatable)) =
            (capacity.get("memory"), allocatable.get("memory"))
        {
            let capacity_str = &memory_capacity.0;
            let allocatable_str = &memory_allocatable.0;

            if allocatable_str != capacity_str {
                warn!("Node {} has reserved memory resources", node_name);
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
