//! Certificate-related inspection: CSR (CertificateSigningRequest) status and TLS certificate expiry from Secrets.
//! Note: apiserver/etcd/kubelet certificate expiry is not exposed via the Kubernetes API;
//! use `kubeadm cert check-expiry` or similar on control-plane nodes.

use anyhow::Result;
use chrono::Utc;
use kube::api::ListParams;
use x509_parser::pem::Pem;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct CertificateInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> CertificateInspector<'a> {
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

        let csr_check = self.inspect_csrs(&mut issues).await?;
        checks.push(csr_check);

        let (tls_check, certificate_expiries) = self.inspect_tls_certificates().await?;
        checks.push(tls_check);

        let overall_score = if checks.is_empty() {
            100.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues.clone());

        Ok(InspectionResult {
            inspection_type: "Certificates".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: if certificate_expiries.is_empty() {
                None
            } else {
                Some(certificate_expiries)
            },
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    /// List TLS secrets, parse tls.crt, and return (CheckResult, CertificateExpiryRow list).
    async fn inspect_tls_certificates(&self) -> Result<(CheckResult, Vec<CertificateExpiryRow>)> {
        let secrets_api = self.client.secrets(None);
        let list = secrets_api.list(&ListParams::default()).await?;
        let mut rows = Vec::new();
        let mut total_certs = 0usize;
        let mut expiring_90 = 0usize;
        let mut expiring_30 = 0usize;
        let mut expired = 0usize;

        for secret in &list.items {
            let st = secret.type_.as_deref().unwrap_or("");
            if st != "kubernetes.io/tls" {
                continue;
            }
            let namespace = secret
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let name = secret
                .metadata
                .name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let data = match &secret.data {
                Some(d) => d,
                None => continue,
            };
            let tls_crt = match data.get("tls.crt") {
                Some(b) => b,
                None => continue,
            };
            let pem_bytes = tls_crt.0.as_slice();
            if pem_bytes.is_empty() {
                continue;
            }
            for pem in Pem::iter_from_buffer(pem_bytes).flatten() {
                let x509 = match pem.parse_x509() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                total_certs += 1;
                let subject = x509.subject().to_string().trim().to_string();
                let subject_short = if subject.len() > 60 {
                    format!("{}...", subject.chars().take(57).collect::<String>())
                } else {
                    subject.clone()
                };
                let validity = x509.validity();
                let expiry_utc = format!("{}", validity.not_after);
                let days = match validity.time_to_expiration() {
                    Some(d) => d.whole_days(),
                    None => {
                        let now = time::OffsetDateTime::now_utc();
                        let not_after = validity.not_after.to_datetime();
                        (not_after - now).whole_days()
                    }
                };
                if days < 0 {
                    expired += 1;
                } else if days <= 30 {
                    expiring_30 += 1;
                } else if days <= 90 {
                    expiring_90 += 1;
                }
                rows.push(CertificateExpiryRow {
                    secret_namespace: namespace.clone(),
                    secret_name: name.clone(),
                    subject_or_cn: subject_short,
                    expiry_utc,
                    days_until_expiry: days,
                });
            }
        }

        let details = if total_certs == 0 {
            self.lang
                .t("No TLS secrets found.", "未找到 TLS Secret。")
                .to_string()
        } else {
            crate::lang_fmt!(
                self.lang,
                "{} certificate(s); {} expiring in 90 days, {} in 30 days, {} expired.",
                "{} 个证书；{} 个将在 90 天内过期，{} 个在 30 天内过期，{} 个已过期。",
                total_certs,
                expiring_90,
                expiring_30,
                expired
            )
        };
        let score = if expired > 0 {
            40.0
        } else if expiring_30 > 0 {
            70.0
        } else if expiring_90 > 0 {
            85.0
        } else {
            100.0
        };
        let status = if score >= 90.0 {
            CheckStatus::Pass
        } else if score >= 70.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };
        let check = CheckResult {
            name: "TLS certificate expiry".to_string(),
            description: self.lang.t(
                "Lists TLS certificates from Secrets (type kubernetes.io/tls) with expiry and days until expiry. Control-plane certs (apiserver/etcd/kubelet) require node-level checks (e.g. kubeadm cert check-expiry).",
                "列出 Secrets（类型 kubernetes.io/tls）中的 TLS 证书及其过期时间和剩余天数。控制平面证书（apiserver/etcd/kubelet）需要节点级检查（例如 kubeadm cert check-expiry）。"
            ).to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(details),
            recommendations: if expiring_30 > 0 || expired > 0 {
                vec![self.lang.t(
                    "Renew expiring or expired TLS certificates. Update the Secret and restart workloads.",
                    "续期即将过期或已过期的 TLS 证书。更新 Secret 并重启工作负载。"
                ).to_string()]
            } else {
                vec![]
            },
        };
        Ok((check, rows))
    }

    async fn inspect_csrs(&self, issues: &mut Vec<Issue>) -> Result<CheckResult> {
        let api = self.client.certificate_signing_requests();
        let list = api.list(&ListParams::default()).await?;
        let total = list.items.len();
        let mut pending = 0usize;
        let mut denied_or_failed = 0usize;

        for csr in &list.items {
            let name = csr
                .metadata
                .name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let status = csr.status.as_ref();
            let conditions = status.and_then(|s| s.conditions.as_ref());
            let has_approved = conditions
                .map(|c| {
                    c.iter()
                        .any(|x| x.type_ == "Approved" && x.status == "True")
                })
                .unwrap_or(false);
            let has_denied = conditions
                .map(|c| c.iter().any(|x| x.type_ == "Denied"))
                .unwrap_or(false);
            let has_failed = conditions
                .map(|c| c.iter().any(|x| x.type_ == "Failed"))
                .unwrap_or(false);

            if has_denied || has_failed {
                denied_or_failed += 1;
                issues.push(Issue {
                    severity: IssueSeverity::Warning,
                    category: "Certificates".to_string(),
                    description: crate::lang_fmt!(
                        self.lang,
                        "CSR {} is {}",
                        "CSR {} 为 {}",
                        name,
                        if has_denied {
                            self.lang.t("Denied", "已拒绝")
                        } else {
                            self.lang.t("Failed", "已失败")
                        }
                    ),
                    resource: Some(name.clone()),
                    recommendation: self
                        .lang
                        .t(
                            "Review and clean up denied/failed CSRs; re-issue if needed.",
                            "审查并清理已拒绝/失败的 CSR；如有需要请重新签发。",
                        )
                        .to_string(),
                    rule_id: Some("B01".to_string()),
                });
            } else if !has_approved {
                pending += 1;
                issues.push(Issue {
                    severity: IssueSeverity::Info,
                    category: "Certificates".to_string(),
                    description: crate::lang_fmt!(self.lang,
                            "CSR {} is Pending approval",
                            "CSR {} 正在等待审批",
                        name
                    ),
                    resource: Some(name),
                    recommendation: self.lang.t(
                        "Approve or deny pending CSRs (e.g. kubectl certificate approve/deny). Cluster component cert expiry (apiserver/etcd/kubelet) must be checked on nodes (e.g. kubeadm cert check-expiry).",
                        "审批或拒绝待处理的 CSR（例如 kubectl certificate approve/deny）。集群组件证书过期（apiserver/etcd/kubelet）必须在节点上检查（例如 kubeadm cert check-expiry）。"
                    ).to_string(),
                    rule_id: Some("B01".to_string()),
                });
            }
        }

        let score = if total == 0 {
            100.0
        } else {
            let bad = pending + denied_or_failed;
            (1.0 - (bad as f64 / total as f64).min(1.0)) * 100.0
        };

        let status = if score >= 90.0 {
            CheckStatus::Pass
        } else if score >= 70.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "CertificateSigningRequests".to_string(),
            description: self.lang.t(
                "Checks CSR status (Pending/Approved/Denied/Failed). Component cert expiry (apiserver/etcd/kubelet) requires node-level checks.",
                "检查 CSR 状态（Pending/Approved/Denied/Failed）。组件证书过期（apiserver/etcd/kubelet）需要节点级检查。"
            ).to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(self.lang,
                    "{} total, {} pending, {} denied/failed",
                    "共 {} 个，{} 个待处理，{} 个已拒绝/失败",
                total, pending, denied_or_failed
            )),
            recommendations: if pending > 0 || denied_or_failed > 0 {
                vec![self.lang.t(
                    "Review CSRs; approve or clean up as needed. For apiserver/etcd/kubelet certificate expiry, run kubeadm cert check-expiry on control-plane nodes.",
                    "检查 CSR；按需审批或清理。对于 apiserver/etcd/kubelet 证书过期，请在控制平面节点上运行 kubeadm cert check-expiry。"
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
