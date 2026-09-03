use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::core::v1::{ComponentStatus, Pod};
use kube::{api::ListParams, Api};

/// ComponentStatus API was removed in Kubernetes 1.24; list can return 404 or "not found".
fn is_component_status_unavailable(err: &kube::Error) -> bool {
    match err {
        kube::Error::Api(ae) => {
            ae.code == 404
                || ae.code == 410
                || ae.message.contains("could not find the requested resource")
                || ae.reason.eq_ignore_ascii_case("NotFound")
        }
        _ => false,
    }
}

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

const CONTROL_PLANE_POD_KEYWORDS: [&str; 4] = [
    "kube-apiserver",
    "kube-controller-manager",
    "kube-scheduler",
    "etcd",
];

pub struct ControlPlaneInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> ControlPlaneInspector<'a> {
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

        // Component status check
        let component_check = self.inspect_component_statuses(&mut issues).await?;
        checks.push(component_check);

        // Control-plane pod check
        let pod_check = self.inspect_control_plane_pods(&mut issues).await?;
        checks.push(pod_check);

        let overall_score = if checks.is_empty() {
            0.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Control Plane".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn inspect_component_statuses(&self, issues: &mut Vec<Issue>) -> Result<CheckResult> {
        let api: Api<ComponentStatus> = Api::all(self.client.client().clone());
        let statuses = match api.list(&ListParams::default()).await {
            Ok(s) => s,
            Err(e) if is_component_status_unavailable(&e) => {
                return Ok(CheckResult {
                    name: "Component Status".to_string(),
                    description: self
                        .lang
                        .t(
                            "Checks the health of core control-plane components",
                            "检查核心控制平面组件的健康状态"
                        )
                        .to_string(),
                    status: CheckStatus::Pass,
                    score: 100.0,
                    max_score: 100.0,
                    details: Some(
                        self.lang
                            .t(
                                "Component Status API not available (e.g. Kubernetes 1.24+); check skipped.",
                                "Component Status API 不可用（例如 Kubernetes 1.24+）；已跳过检查。"
                            )
                            .to_string(),
                    ),
                    recommendations: vec![],
                });
            }
            Err(e) => return Err(e.into()),
        };

        let total = statuses.items.len();
        let mut healthy = 0usize;

        for status in statuses {
            let name = status
                .metadata
                .name
                .unwrap_or_else(|| "unknown".to_string());
            if let Some(conditions) = status.conditions {
                let mut component_healthy = true;
                for condition in conditions {
                    if condition.status.as_str() != "True" {
                        component_healthy = false;
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "ControlPlane".to_string(),
                            description: crate::lang_fmt!(self.lang,
                                    "Component {} reports {} = {}",
                                    "组件 {} 报告 {} = {}",
                                name, condition.type_, condition.status
                            ),
                            resource: Some(name.clone()),
                            recommendation: self.lang.t(
                                "Inspect control-plane logs and ensure all components are running and healthy.",
                                "检查控制平面日志并确保所有组件正常运行且健康。"
                            ).to_string(),
                            rule_id: Some("601".to_string()),
                        });
                    }
                }
                if component_healthy {
                    healthy += 1;
                }
            }
        }

        let score = if total == 0 {
            0.0
        } else {
            (healthy as f64 / total as f64) * 100.0
        };

        let status = if score >= 99.9 {
            CheckStatus::Pass
        } else if score >= 80.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "Component Status".to_string(),
            description: self
                .lang
                .t(
                    "Checks the health of core control-plane components",
                    "检查核心控制平面组件的健康状态",
                )
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} components healthy",
                "{}/{} 个组件健康",
                healthy,
                total
            )),
            recommendations: if score < 100.0 {
                vec![self
                    .lang
                    .t(
                        "Review kube-system pod logs and ensure all static pods are Running.",
                        "检查 kube-system Pod 日志并确保所有静态 Pod 处于运行状态。",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        })
    }

    async fn inspect_control_plane_pods(&self, issues: &mut Vec<Issue>) -> Result<CheckResult> {
        let pods_api = self.client.pods(Some("kube-system"));
        let pods = pods_api.list(&ListParams::default()).await?;

        let mut evaluated = 0usize;
        let mut healthy = 0usize;

        for pod in pods.items {
            if let Some(name) = pod.metadata.name.clone() {
                if CONTROL_PLANE_POD_KEYWORDS.iter().any(|k| name.contains(k)) {
                    evaluated += 1;
                    if !is_pod_running(&pod) {
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "ControlPlane".to_string(),
                            description: crate::lang_fmt!(self.lang,
                                    "Control plane pod {} is not running",
                                    "控制平面 Pod {} 未运行",
                                name
                            ),
                            resource: Some(name.clone()),
                            recommendation: self
                                .lang
                                .t(
                                    "Check the static pod manifest and node health for this component.",
                                    "检查此组件的静态 Pod 清单和节点健康状态。"
                                )
                                .to_string(),
                            rule_id: Some("602".to_string()),
                        });
                    } else {
                        healthy += 1;
                    }
                }
            }
        }

        let score = if evaluated == 0 {
            100.0
        } else {
            (healthy as f64 / evaluated as f64) * 100.0
        };

        let status = if score >= 99.9 {
            CheckStatus::Pass
        } else if score >= 80.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "Control Plane Pods".to_string(),
            description: self
                .lang
                .t(
                    "Validates that key control-plane pods in kube-system are running",
                    "验证 kube-system 中的关键控制平面 Pod 是否正在运行",
                )
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(if evaluated == 0 {
                self.lang
                    .t(
                        "No static control-plane pods detected (managed control plane?)",
                        "未检测到静态控制平面 Pod（托管控制平面？）",
                    )
                    .to_string()
            } else {
                crate::lang_fmt!(
                    self.lang,
                    "{}/{} control-plane pods running",
                    "{}/{} 个控制平面 Pod 正在运行",
                    healthy,
                    evaluated
                )
            }),
            recommendations: if score < 100.0 {
                vec![self.lang.t(
                    "Ensure kube-apiserver, controller-manager, scheduler, and etcd pods are running without restarts.",
                    "确保 kube-apiserver、controller-manager、scheduler 和 etcd Pod 正在运行且没有重启。"
                ).to_string()]
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

fn is_pod_running(pod: &Pod) -> bool {
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
