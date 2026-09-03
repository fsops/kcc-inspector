use anyhow::Result;
use chrono::Utc;
use kube::api::ListParams;
use log::info;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct StorageInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> StorageInspector<'a> {
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
        info!("Starting storage inspection");

        let mut checks = Vec::new();
        let mut issues = Vec::new();

        // Check Persistent Volumes
        let pv_api = self.client.persistent_volumes();
        let pvs = pv_api.list(&ListParams::default()).await?;

        let mut total_pvs = 0;
        let mut available_pvs = 0;
        let mut bound_pvs = 0;
        let mut failed_pvs = 0;

        for pv in &pvs.items {
            let pv_name = pv.metadata.name.as_deref().unwrap_or("unknown");
            total_pvs += 1;

            if let Some(status) = &pv.status {
                match status.phase.as_deref() {
                    Some("Available") => available_pvs += 1,
                    Some("Bound") => bound_pvs += 1,
                    Some("Failed") => {
                        failed_pvs += 1;
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "PersistentVolume".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Persistent Volume {} is in Failed state",
                                "持久卷 {} 处于失败状态",
                                pv_name
                            ),
                            resource: Some(pv_name.to_string()),
                            recommendation: self
                                .lang
                                .t(
                                    "Check PV configuration and underlying storage",
                                    "检查 PV 配置和底层存储",
                                )
                                .to_string(),
                            rule_id: Some("401".to_string()),
                        });
                    }
                    Some("Released") => {
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "PersistentVolume".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "Persistent Volume {} is Released but not reclaimed",
                                "持久卷 {} 已释放但未被回收",
                                pv_name
                            ),
                            resource: Some(pv_name.to_string()),
                            recommendation: self
                                .lang
                                .t(
                                    "Check reclaim policy and clean up released PVs",
                                    "检查回收策略并清理已释放的 PV",
                                )
                                .to_string(),
                            rule_id: Some("402".to_string()),
                        });
                    }
                    _ => {}
                }
            }

            // Check PV reclaim policy
            if let Some(spec) = &pv.spec {
                match spec.persistent_volume_reclaim_policy.as_deref() {
                    Some("Delete") => {
                        // This is fine for dynamic provisioning
                    }
                    Some("Retain") => {
                        // This might accumulate orphaned PVs
                        if pv.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Released") {
                            issues.push(Issue {
                                severity: IssueSeverity::Info,
                                category: "PersistentVolume".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "PV {} with Retain policy is Released",
                                    "具有 Retain 策略的 PV {} 已释放",
                                    pv_name
                                ),
                                resource: Some(pv_name.to_string()),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Monitor and clean up retained PVs manually",
                                        "手动监控并清理保留的 PV",
                                    )
                                    .to_string(),
                                rule_id: Some("403".to_string()),
                            });
                        }
                    }
                    _ => {
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "PersistentVolume".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "PV {} has unclear reclaim policy",
                                "PV {} 的回收策略不明确",
                                pv_name
                            ),
                            resource: Some(pv_name.to_string()),
                            recommendation: self
                                .lang
                                .t(
                                    "Set explicit reclaim policy (Retain or Delete)",
                                    "设置明确的回收策略（Retain 或 Delete）",
                                )
                                .to_string(),
                            rule_id: Some("404".to_string()),
                        });
                    }
                }
            }
        }

        // Check Persistent Volume Claims
        let pvc_api = self.client.persistent_volume_claims(namespace);
        let pvcs = pvc_api.list(&ListParams::default()).await?;

        let mut total_pvcs = 0;
        let mut bound_pvcs = 0;
        let mut _pending_pvcs = 0;

        for pvc in &pvcs.items {
            let pvc_name = pvc.metadata.name.as_deref().unwrap_or("unknown");
            let pvc_namespace = pvc.metadata.namespace.as_deref().unwrap_or("default");
            total_pvcs += 1;

            if let Some(status) = &pvc.status {
                match status.phase.as_deref() {
                    Some("Bound") => bound_pvcs += 1,
                    Some("Pending") => {
                        _pending_pvcs += 1;
                        issues.push(Issue {
                            severity: IssueSeverity::Warning,
                            category: "PersistentVolumeClaim".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "PVC {}/{} is pending",
                                "PVC {}/{} 处于等待状态",
                                pvc_namespace,
                                pvc_name
                            ),
                            resource: Some(format!("{}/{}", pvc_namespace, pvc_name)),
                            recommendation: self
                                .lang
                                .t(
                                    "Check storage class availability and node capacity",
                                    "检查存储类可用性和节点容量",
                                )
                                .to_string(),
                            rule_id: Some("405".to_string()),
                        });
                    }
                    Some("Lost") => {
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "PersistentVolumeClaim".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "PVC {}/{} is lost",
                                "PVC {}/{} 已丢失",
                                pvc_namespace,
                                pvc_name
                            ),
                            resource: Some(format!("{}/{}", pvc_namespace, pvc_name)),
                            recommendation: self
                                .lang
                                .t(
                                    "Data may be lost, check backup and recovery procedures",
                                    "数据可能丢失，请检查备份和恢复流程",
                                )
                                .to_string(),
                            rule_id: Some("406".to_string()),
                        });
                    }
                    _ => {}
                }
            }

            // Check if PVC uses storage class
            if let Some(spec) = &pvc.spec {
                if spec.storage_class_name.is_none() {
                    issues.push(Issue {
                        severity: IssueSeverity::Info,
                        category: "PersistentVolumeClaim".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "PVC {}/{} has no storage class specified",
                            "PVC {}/{} 未指定存储类",
                            pvc_namespace,
                            pvc_name
                        ),
                        resource: Some(format!("{}/{}", pvc_namespace, pvc_name)),
                        recommendation: self
                            .lang
                            .t(
                                "Specify storage class for better provisioning control",
                                "指定存储类以获得更好的供应控制",
                            )
                            .to_string(),
                        rule_id: Some("407".to_string()),
                    });
                }
            }
        }

        // Check Storage Classes
        let sc_api = self.client.storage_classes();
        let storage_classes = sc_api.list(&ListParams::default()).await?;

        let mut total_storage_classes = 0;
        let mut default_storage_classes = 0;

        for sc in &storage_classes.items {
            let sc_name = sc.metadata.name.as_deref().unwrap_or("unknown");
            total_storage_classes += 1;

            if let Some(annotations) = &sc.metadata.annotations {
                if annotations.get("storageclass.kubernetes.io/is-default-class")
                    == Some(&"true".to_string())
                {
                    default_storage_classes += 1;
                }
            }

            // Check provisioner
            if sc.provisioner.is_empty() {
                issues.push(Issue {
                    severity: IssueSeverity::Critical,
                    category: "StorageClass".to_string(),
                    description: crate::lang_fmt!(
                        self.lang,
                        "Storage class {} has no provisioner",
                        "存储类 {} 没有 provisioner",
                        sc_name
                    ),
                    resource: Some(sc_name.to_string()),
                    recommendation: self
                        .lang
                        .t(
                            "Configure proper provisioner for storage class",
                            "为存储类配置正确的 provisioner",
                        )
                        .to_string(),
                    rule_id: Some("408".to_string()),
                });
            }
        }

        // Check for proper default storage class configuration
        if default_storage_classes == 0 {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "StorageClass".to_string(),
                description: self
                    .lang
                    .t("No default storage class configured", "未配置默认存储类")
                    .to_string(),
                resource: None,
                recommendation: self
                    .lang
                    .t(
                        "Configure a default storage class for automatic PV provisioning",
                        "配置默认存储类以实现 PV 自动供应",
                    )
                    .to_string(),
                rule_id: Some("409".to_string()),
            });
        } else if default_storage_classes > 1 {
            issues.push(Issue {
                severity: IssueSeverity::Warning,
                category: "StorageClass".to_string(),
                description: crate::lang_fmt!(
                    self.lang,
                    "{} default storage classes configured",
                    "配置了 {} 个默认存储类",
                    default_storage_classes
                ),
                resource: None,
                recommendation: self
                    .lang
                    .t(
                        "Only one storage class should be marked as default",
                        "只能将一个存储类标记为默认",
                    )
                    .to_string(),
                rule_id: Some("410".to_string()),
            });
        }

        // PV health check
        let pv_health_score = if total_pvs > 0 {
            ((total_pvs - failed_pvs) as f64 / total_pvs as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "Persistent Volume Health".to_string(),
            description: self
                .lang
                .t(
                    "Checks if persistent volumes are in healthy state",
                    "检查持久卷是否处于健康状态",
                )
                .to_string(),
            status: if pv_health_score >= 95.0 {
                CheckStatus::Pass
            } else if pv_health_score >= 80.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: pv_health_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "Available: {}, Bound: {}, Failed: {}, Total: {}",
                "可用：{}，已绑定：{}，失败：{}，总数：{}",
                available_pvs,
                bound_pvs,
                failed_pvs,
                total_pvs
            )),
            recommendations: if pv_health_score < 95.0 {
                vec![self
                    .lang
                    .t(
                        "Investigate and resolve failed persistent volumes",
                        "调查并解决失败的持久卷",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        // PVC binding check
        let pvc_binding_score = if total_pvcs > 0 {
            (bound_pvcs as f64 / total_pvcs as f64) * 100.0
        } else {
            100.0
        };

        checks.push(CheckResult {
            name: "PVC Binding".to_string(),
            description: self
                .lang
                .t(
                    "Checks if persistent volume claims are properly bound",
                    "检查持久卷声明是否正确绑定",
                )
                .to_string(),
            status: if pvc_binding_score >= 95.0 {
                CheckStatus::Pass
            } else if pvc_binding_score >= 80.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: pvc_binding_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} PVCs are bound",
                "{}/{} 个 PVC 已绑定",
                bound_pvcs,
                total_pvcs
            )),
            recommendations: if pvc_binding_score < 95.0 {
                vec![self
                    .lang
                    .t(
                        "Resolve pending PVCs and check storage availability",
                        "解决等待中的 PVC 并检查存储可用性",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        // Storage class configuration check
        let sc_config_score = if total_storage_classes > 0 && default_storage_classes == 1 {
            100.0
        } else if total_storage_classes > 0 {
            80.0
        } else {
            60.0
        };

        checks.push(CheckResult {
            name: "Storage Class Configuration".to_string(),
            description: self
                .lang
                .t(
                    "Checks storage class setup and default configuration",
                    "检查存储类配置和默认设置",
                )
                .to_string(),
            status: if sc_config_score >= 90.0 {
                CheckStatus::Pass
            } else if sc_config_score >= 60.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Critical
            },
            score: sc_config_score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{} storage classes, {} default",
                "{} 个存储类，{} 个默认",
                total_storage_classes,
                default_storage_classes
            )),
            recommendations: if sc_config_score < 90.0 {
                vec![self
                    .lang
                    .t(
                        "Configure appropriate storage classes and set one as default",
                        "配置合适的存储类并将一个设为默认",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        });

        let overall_score = checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64;

        let summary = self.create_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Storage".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
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
