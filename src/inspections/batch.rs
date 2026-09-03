use anyhow::Result;
use chrono::Utc;
use k8s_openapi::api::batch::v1::Job;
use kube::api::ListParams;

use crate::inspections::types::*;
use crate::k8s::K8sClient;
use crate::utils::lang::Lang;

pub struct BatchInspector<'a> {
    client: &'a K8sClient,
    lang: Lang,
}

impl<'a> BatchInspector<'a> {
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

        let cron_check = self.inspect_cron_jobs(namespace, &mut issues).await?;
        let job_check = self.inspect_jobs(namespace, &mut issues).await?;

        checks.push(cron_check);
        checks.push(job_check);

        let overall_score = if checks.is_empty() {
            0.0
        } else {
            checks.iter().map(|c| c.score).sum::<f64>() / checks.len() as f64
        };

        let summary = self.build_summary(&checks, issues);

        Ok(InspectionResult {
            inspection_type: "Batch Workloads".to_string(),
            timestamp: Utc::now(),
            overall_score,
            checks,
            summary,
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        })
    }

    async fn inspect_cron_jobs(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let cron_api = self.client.cron_jobs(namespace);
        let cron_jobs = cron_api.list(&ListParams::default()).await?;

        if cron_jobs.items.is_empty() {
            return Ok(CheckResult {
                name: "CronJobs".to_string(),
                description: self
                    .lang
                    .t(
                        "Evaluates CronJob health and schedules",
                        "评估 CronJob 的健康状态和调度",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 70.0,
                max_score: 100.0,
                details: Some(
                    self.lang
                        .t("No CronJobs detected", "未检测到 CronJob")
                        .to_string(),
                ),
                recommendations: vec![self
                    .lang
                    .t(
                        "Introduce CronJobs for periodic tasks where applicable.",
                        "在适用的情况下引入 CronJob 执行定期任务。",
                    )
                    .to_string()],
            });
        }

        let mut healthy = 0usize;
        for cron in &cron_jobs.items {
            let name = cron
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            if let Some(spec) = &cron.spec {
                if spec.suspend == Some(true) {
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "Batch".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "CronJob {} is suspended",
                            "CronJob {} 已暂停",
                            name
                        ),
                        resource: Some(name.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Enable CronJob or remove if no longer needed.",
                                "启用 CronJob，如果不再需要则删除。",
                            )
                            .to_string(),
                        rule_id: Some("801".to_string()),
                    });
                    continue;
                }
            }

            if let Some(status) = &cron.status {
                let last_schedule = status.last_schedule_time.as_ref().map(|t| t.0);
                let last_success = status.last_successful_time.as_ref().map(|t| t.0);

                if let Some(schedule_time) = last_schedule {
                    if last_success.map(|s| s < schedule_time).unwrap_or(true) {
                        issues.push(Issue {
                            severity: IssueSeverity::Critical,
                            category: "Batch".to_string(),
                            description: crate::lang_fmt!(
                                self.lang,
                                "CronJob {} last run failed",
                                "CronJob {} 上次运行失败",
                                name
                            ),
                            resource: Some(name.clone()),
                            recommendation: self
                                .lang
                                .t(
                                    "Check CronJob job logs and fix failures before next schedule.",
                                    "检查 CronJob 作业日志并在下次调度前修复失败。",
                                )
                                .to_string(),
                            rule_id: Some("802".to_string()),
                        });
                        continue;
                    }
                }

                if last_schedule.is_none() {
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "Batch".to_string(),
                        description: crate::lang_fmt!(
                            self.lang,
                            "CronJob {} never executed",
                            "CronJob {} 从未执行",
                            name
                        ),
                        resource: Some(name.clone()),
                        recommendation: self
                            .lang
                            .t(
                                "Ensure CronJob schedule is correct and controller is running.",
                                "确保 CronJob 调度正确且控制器正在运行。",
                            )
                            .to_string(),
                        rule_id: Some("803".to_string()),
                    });
                    continue;
                }
            }
            healthy += 1;
        }

        let score = (healthy as f64 / cron_jobs.items.len() as f64) * 100.0;
        let status = if score >= 90.0 {
            CheckStatus::Pass
        } else if score >= 70.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "CronJobs".to_string(),
            description: self
                .lang
                .t(
                    "Checks CronJob scheduling and execution status",
                    "检查 CronJob 的调度和执行状态",
                )
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} CronJobs healthy",
                "{}/{} 个 CronJob 健康",
                healthy,
                cron_jobs.items.len()
            )),
            recommendations: if score < 90.0 {
                vec![self
                    .lang
                    .t(
                        "Review CronJob failure events and tune schedule or retry policy.",
                        "检查 CronJob 失败事件并调整调度或重试策略。",
                    )
                    .to_string()]
            } else {
                vec![]
            },
        })
    }

    async fn inspect_jobs(
        &self,
        namespace: Option<&str>,
        issues: &mut Vec<Issue>,
    ) -> Result<CheckResult> {
        let job_api: kube::Api<Job> = if let Some(ns) = namespace {
            kube::Api::namespaced(self.client.client().clone(), ns)
        } else {
            kube::Api::all(self.client.client().clone())
        };
        let jobs = job_api.list(&ListParams::default()).await?;

        if jobs.items.is_empty() {
            return Ok(CheckResult {
                name: "Jobs".to_string(),
                description: self
                    .lang
                    .t(
                        "Evaluates Job completion and failure retries",
                        "评估 Job 的完成情况和失败重试",
                    )
                    .to_string(),
                status: CheckStatus::Warning,
                score: 70.0,
                max_score: 100.0,
                details: Some(self.lang.t("No Jobs detected", "未检测到 Job").to_string()),
                recommendations: vec![self
                    .lang
                    .t(
                        "Use Jobs for one-off batch workloads when needed.",
                        "在需要时使用 Job 执行一次性批处理工作负载。",
                    )
                    .to_string()],
            });
        }

        let mut healthy = 0usize;
        for job in &jobs.items {
            let name = job
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            if let Some(status) = &job.status {
                if status.failed.unwrap_or(0) > 0 {
                    issues.push(Issue {
                        severity: IssueSeverity::Warning,
                        category: "Batch".to_string(),
                        description: crate::lang_fmt!(self.lang, "Job {} has failed pods", "Job {} 有失败的 Pod",
                            name
                        ),
                        resource: Some(name.clone()),
                        recommendation: self.lang.t(
                            "Inspect job pod logs and adjust backoffLimit or resource requests.",
                            "检查 Job Pod 日志并调整 backoffLimit 或资源请求。"
                        ).to_string(),
                        rule_id: Some("804".to_string()),
                    });
                    continue;
                }

                if status.active.unwrap_or(0) > 0 && status.succeeded.unwrap_or(0) == 0 {
                    if let Some(start) = status.start_time.as_ref() {
                        let elapsed = Utc::now() - start.0;
                        if elapsed.num_minutes() > 60 {
                            issues.push(Issue {
                                severity: IssueSeverity::Warning,
                                category: "Batch".to_string(),
                                description: crate::lang_fmt!(
                                    self.lang,
                                    "Job {} running for over 60 minutes",
                                    "Job {} 已运行超过 60 分钟",
                                    name
                                ),
                                resource: Some(name.clone()),
                                recommendation: self
                                    .lang
                                    .t(
                                        "Check for stuck pods or adjust activeDeadlineSeconds.",
                                        "检查是否有卡住的 Pod，或调整 activeDeadlineSeconds。",
                                    )
                                    .to_string(),
                                rule_id: Some("805".to_string()),
                            });
                            continue;
                        }
                    }
                }
            }
            healthy += 1;
        }

        let score = (healthy as f64 / jobs.items.len() as f64) * 100.0;
        let status = if score >= 90.0 {
            CheckStatus::Pass
        } else if score >= 70.0 {
            CheckStatus::Warning
        } else {
            CheckStatus::Critical
        };

        Ok(CheckResult {
            name: "Jobs".to_string(),
            description: self
                .lang
                .t(
                    "Checks Jobs for stuck or failed executions",
                    "检查 Job 是否卡住或失败",
                )
                .to_string(),
            status,
            score,
            max_score: 100.0,
            details: Some(crate::lang_fmt!(
                self.lang,
                "{}/{} Jobs healthy",
                "{}/{} 个 Job 健康",
                healthy,
                jobs.items.len()
            )),
            recommendations: if score < 90.0 {
                vec![self
                    .lang
                    .t(
                        "Review job failure events and tune retries/backoff.",
                        "检查 Job 失败事件并调整重试/退避。",
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
