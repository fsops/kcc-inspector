use anyhow::Result;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;

use crate::inspections::issue_codes;
use crate::inspections::types::*;
use crate::node_inspection::types::NodeDiskMount;
use crate::node_inspection::NodeInspectionResult;
use crate::reporting::report_resource::{issue_to_resource_key, REPORT_RESOURCE_ORDER};
use crate::scoring::scoring_engine::ScoringEngine;
use crate::utils::format::truncate_string;
use crate::utils::lang::{Lang, Strings};

const DEFAULT_MAX_RECOMMENDATIONS: usize = 5;

/// Which check statuses to include in the Check Results table. Default is Warning, Critical, Error (exclude Pass).
#[derive(Clone, Debug)]
pub enum CheckLevelFilter {
    All,
    Only(Vec<CheckStatus>),
}

/// Parse --check-level string: "all" or comma-separated e.g. "warning,critical,error".
pub fn parse_check_level_filter(s: &str) -> CheckLevelFilter {
    let s = s.trim().to_lowercase();
    if s == "all" {
        return CheckLevelFilter::All;
    }
    let mut only = Vec::new();
    for part in s.split(',') {
        match part.trim() {
            "pass" => only.push(CheckStatus::Pass),
            "warning" => only.push(CheckStatus::Warning),
            "critical" => only.push(CheckStatus::Critical),
            "error" => only.push(CheckStatus::Error),
            _ => {}
        }
    }
    if only.is_empty() {
        CheckLevelFilter::Only(vec![
            CheckStatus::Warning,
            CheckStatus::Critical,
            CheckStatus::Error,
        ])
    } else {
        CheckLevelFilter::Only(only)
    }
}

/// Short title for an issue code in the requested language.
fn issue_short_title(lang: Lang, code: &str) -> Option<String> {
    match lang {
        Lang::Zh => issue_codes::short_title_zh(issue_codes::strip_prefix(code)).map(String::from),
        Lang::En => issue_codes::short_title(issue_codes::strip_prefix(code)).map(String::from),
    }
}

/// 报告中展示的问题代码：去掉类别前缀（RES-202 → 202、CERT-B02 → B02、OBS-A01 → A01）。
/// 当前巡检模块产出的 rule_id 已是纯编号（如 202、B02），此函数仅做防御性归一化，
/// 兼容仍带前缀的旧数据。
fn display_issue_code(code: &str) -> String {
    issue_codes::strip_prefix(code).to_string()
}

/// 问题代码表格单元格：有代码则渲染为 `202`，无代码则显示 `-`。
fn code_cell(rule_id: Option<&str>) -> String {
    match rule_id {
        Some(c) => format!("`{}`", display_issue_code(c)),
        None => "-".to_string(),
    }
}

/// Flatten all issues from inspections and group by canonical resource key.
fn group_issues_by_resource(report: &ClusterReport) -> HashMap<String, Vec<Issue>> {
    let mut map: HashMap<String, Vec<Issue>> = HashMap::new();
    for inspection in &report.inspections {
        for issue in &inspection.summary.issues {
            let key = issue_to_resource_key(issue);
            map.entry(key).or_default().push(issue.clone());
        }
    }
    map
}

/// Maps inspection type name to a cluster-recognizable resource object for the Check Results table.
fn inspection_type_to_resource(inspection_type: &str) -> &'static str {
    match inspection_type {
        "Node Health" | "Node Inspection" => "Node",
        "Control Plane" => "Control Plane",
        "Network Connectivity" => "Service",
        "Storage" => "PersistentVolume",
        "Resource Usage" => "Pod",
        "Pod Status" => "Pod",
        "Autoscaling" => "HorizontalPodAutoscaler",
        "Batch Workloads" => "Job",
        "Security Configuration" => "NetworkPolicy",
        "Policy & Governance" => "ResourceQuota",
        "Observability" => "Observability",
        "Namespace" => "Namespace",
        "Certificates" => "Certificate",
        "Upgrade Readiness" => "Node",
        _ => "Other",
    }
}

/// Format affected resources for table cells: one resource per line (Markdown line break: "  \n").
fn format_affected_resources(resources: &[String]) -> String {
    resources
        .iter()
        .map(|r| format!("`{}`", r))
        .collect::<Vec<_>>()
        .join("  \n")
}

/// Convert pod-mounted path to host perspective. Strips /host prefix so /host/boot -> /boot, /host -> /.
fn host_path_display(path: &str) -> String {
    if path == "/host" {
        return "/".to_string();
    }
    if let Some(rest) = path.strip_prefix("/host/") {
        return rest.to_string();
    }
    path.to_string()
}

/// 目录层级深度（仅用于排序）："/" 为 0，"/data" 为 1，"/data/disk1" 为 2。
fn mount_depth(mp: &str) -> usize {
    if mp == "/" {
        0
    } else {
        mp.trim_start_matches('/').split('/').count()
    }
}

/// 把分区设备名归一化为物理磁盘名（保留 /dev/ 前缀）：
/// "/dev/sda1" -> "/dev/sda"，"/dev/nvme0n1p1" -> "/dev/nvme0n1"，"/dev/mmcblk0p1" -> "/dev/mmcblk0"；
/// mapper/dm-*/loop* 等虚拟设备或整盘设备原样保留。
fn normalize_device(dev: &str) -> String {
    if !dev.starts_with("/dev/") {
        return dev.to_string();
    }
    let base = &dev[5..];
    // nvme0n1p1 / mmcblk0p1 -> nvme0n1 / mmcblk0
    if let Some(idx) = base.find('p') {
        let (head, tail) = base.split_at(idx);
        if !head.is_empty()
            && head.ends_with(|c: char| c.is_ascii_digit())
            && tail.len() > 1
            && tail[1..].chars().all(|c| c.is_ascii_digit())
        {
            return format!("/dev/{}", head);
        }
    }
    // sdX/vdX/hdX/xvdX + 数字 -> sdX/vdX/hdX/xvdX（整盘无数字时原样保留）
    let trimmed = base.trim_end_matches(|c: char| c.is_ascii_digit());
    if !trimmed.is_empty()
        && trimmed != base
        && (trimmed.starts_with("sd")
            || trimmed.starts_with("vd")
            || trimmed.starts_with("hd")
            || trimmed.starts_with("xvd"))
    {
        return format!("/dev/{}", trimmed);
    }
    dev.to_string()
}

/// 单个挂载点展示行：(挂载点, 磁盘, 文件系统, 总量, 已用, 使用率)。
type DiskRow = (
    String,
    String,
    String,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// 把节点挂载列表整理为磁盘维度的展示行：按物理磁盘分组（分区设备归一化为磁盘名）；
/// 同一设备同一容量的绑定挂载只保留最浅挂载点（避免 kubelet local-volume 等同一文件系统的重复视图）；
/// 根盘（挂载 / 的盘）排最前，其余磁盘按其最浅挂载深度排序，盘内浅层在前、使用率降序。
/// 不做目录分级折叠、不限制行数。
fn build_disk_rows(disks: &[NodeDiskMount]) -> Vec<DiskRow> {
    // 只保留根目录与真实块设备（tmpfs 等内存盘、loop 回环设备不展示）
    let mut best: HashMap<(String, u64), DiskRow> = HashMap::new();
    for d in disks {
        if d.mount_point != "/"
            && (!d.device.starts_with("/dev/") || d.device.starts_with("/dev/loop"))
        {
            continue;
        }
        let total_bits = d.total_g.map(|g| g.to_bits()).unwrap_or(u64::MAX);
        let key = (d.device.clone(), total_bits);
        let entry = (
            host_path_display(&d.mount_point),
            normalize_device(&d.device),
            d.fstype.clone(),
            d.total_g,
            d.used_g,
            d.used_pct,
        );
        match best.get_mut(&key) {
            Some(prev) if mount_depth(&prev.0) > mount_depth(&entry.0) => {
                *prev = entry;
            }
            Some(_) => {}
            None => {
                best.insert(key, entry);
            }
        }
    }
    let mut rows: Vec<_> = best.into_values().collect();
    // 每个磁盘的最浅挂载深度作为盘间排序依据
    let mut disk_min_depth: HashMap<String, usize> = HashMap::new();
    for r in &rows {
        let d = mount_depth(&r.0);
        disk_min_depth
            .entry(r.1.clone())
            .and_modify(|e| *e = (*e).min(d))
            .or_insert(d);
    }
    let root_disk: Option<String> = rows.iter().find(|r| r.0 == "/").map(|r| r.1.clone());
    rows.sort_by(|a, b| {
        let a_root = root_disk.as_deref() == Some(a.1.as_str());
        let b_root = root_disk.as_deref() == Some(b.1.as_str());
        b_root
            .cmp(&a_root)
            .then_with(|| disk_min_depth[&a.1].cmp(&disk_min_depth[&b.1]))
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| mount_depth(&a.0).cmp(&mount_depth(&b.0)))
            .then_with(|| {
                let pa = a.5.unwrap_or(-1.0);
                let pb = b.5.unwrap_or(-1.0);
                pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.0.cmp(&b.0))
    });
    rows
}

/// Build a Markdown anchor slug from a module title (e.g. "Node Health" -> "node-health").
fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            let lower = if c.is_ascii_uppercase() {
                (c as u8 + 32) as char
            } else {
                c
            };
            out.push(lower);
        } else if (c == ' ' || c == '-') && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

pub struct ReportGenerator {
    #[allow(dead_code)]
    scoring_engine: ScoringEngine,
    lang: Lang,
}

impl ReportGenerator {
    /// Creates a generator using the default report language (Chinese).
    pub fn new() -> Self {
        Self::with_lang(Lang::default())
    }

    /// Creates a generator for a specific report language (`Lang::En` or `Lang::Zh`).
    pub fn with_lang(lang: Lang) -> Self {
        Self {
            scoring_engine: ScoringEngine::new(),
            lang,
        }
    }

    /// Report language in use.
    ///
    /// Public API consumed by integration tests; `#[allow(dead_code)]` because
    /// the binary target compiles this module tree again and never calls it.
    #[allow(dead_code)]
    pub fn lang(&self) -> Lang {
        self.lang
    }

    /// Display strings for the configured language.
    fn tr(&self) -> &'static Strings {
        Strings::get(self.lang)
    }

    /// Cluster name as displayed in the report: the generic "kubernetes" name
    /// (the kubeadm/minikube default) is shown as "default" instead.
    fn cluster_display_name(&self, report: &ClusterReport) -> String {
        if report.cluster_name.to_lowercase().contains("kubernetes") {
            "default".to_string()
        } else {
            report.cluster_name.clone()
        }
    }

    /// Health status label in the configured language.
    fn health_label(&self, status: &HealthStatus) -> &'static str {
        self.lang.health_label(status)
    }

    /// Issue severity label in the configured language.
    fn severity_label(&self, severity: &IssueSeverity) -> &'static str {
        self.lang.severity_label(severity)
    }

    /// `enabled` / `disabled` / `None` cell for the node service status table.
    fn service_status_label(&self, v: Option<bool>) -> &'static str {
        match v {
            Some(true) => self.tr().service_enabled,
            Some(false) => self.tr().service_disabled,
            None => self.tr().service_none,
        }
    }

    /// `Yes` / `No` / `-` cell for boolean columns.
    fn yes_no_label(&self, v: Option<bool>) -> &'static str {
        match v {
            Some(true) => self.tr().yes_label,
            Some(false) => self.tr().no_label,
            None => "-",
        }
    }

    #[allow(dead_code)]
    pub async fn generate_report(
        &self,
        cluster_report: &ClusterReport,
        output_path: &str,
    ) -> Result<()> {
        self.generate_report_with_filters(
            cluster_report,
            output_path,
            None,
            false,
            None,
            None,
            None,
        )
        .await
    }

    /// Returns the main report as Markdown string (same filtering as generate_report_with_filters, no disk write).
    pub fn generate_markdown_string(
        &self,
        cluster_report: &ClusterReport,
        filter_category: Option<&Vec<String>>,
        max_recommendations: Option<usize>,
        min_severity: Option<IssueSeverity>,
        check_level_filter: Option<CheckLevelFilter>,
    ) -> Result<String> {
        let filtered = if let Some(min) = min_severity {
            Self::apply_severity_filter(cluster_report, min)
        } else {
            cluster_report.clone()
        };
        let filtered = if let Some(filters) = filter_category {
            Self::apply_category_filters(&filtered, filters, max_recommendations)
        } else {
            filtered
        };
        self.generate_main_report(&filtered, max_recommendations, check_level_filter)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn generate_report_with_filters(
        &self,
        cluster_report: &ClusterReport,
        output_path: &str,
        filter_category: Option<&Vec<String>>,
        no_summary: bool,
        max_recommendations: Option<usize>,
        min_severity: Option<IssueSeverity>,
        check_level_filter: Option<CheckLevelFilter>,
    ) -> Result<()> {
        let main_report = self.generate_markdown_string(
            cluster_report,
            filter_category,
            max_recommendations,
            min_severity.clone(),
            check_level_filter,
        )?;
        fs::write(output_path, main_report)?;

        if !no_summary {
            let filtered = if let Some(min) = min_severity {
                Self::apply_severity_filter(cluster_report, min)
            } else {
                cluster_report.clone()
            };
            let filtered = if let Some(filters) = filter_category {
                Self::apply_category_filters(&filtered, filters, max_recommendations)
            } else {
                filtered
            };
            let summary_report = self.generate_summary_report(&filtered)?;
            let summary_path = output_path.replace(".md", "-summary.md");
            fs::write(summary_path, summary_report)?;
        }

        Ok(())
    }

    /// Filter report to only include issues with severity >= min_severity; recalc executive summary.
    fn apply_severity_filter(report: &ClusterReport, min_severity: IssueSeverity) -> ClusterReport {
        let mut new_report = report.clone();
        new_report.inspections = report
            .inspections
            .iter()
            .map(|ins| {
                let mut ins_clone = ins.clone();
                ins_clone.summary.issues = ins
                    .summary
                    .issues
                    .iter()
                    .filter(|iss| iss.severity >= min_severity)
                    .cloned()
                    .collect();
                ins_clone
            })
            .collect();

        let engine = ScoringEngine::new();
        let overall = engine.calculate_weighted_score(&new_report.inspections);
        let health = engine.get_health_status(overall);
        let score_breakdown_details = engine.generate_score_breakdown(&new_report.inspections);
        let mut score_breakdown: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        for (k, v) in score_breakdown_details.into_iter() {
            score_breakdown.insert(k, v.score);
        }
        let max_r = DEFAULT_MAX_RECOMMENDATIONS;
        let key_findings = Self::build_aggregated_findings_error_only(&new_report);
        let priority_recommendations = Self::build_aggregated_recommendations(&new_report, max_r);
        new_report.overall_score = overall;
        new_report.executive_summary = ExecutiveSummary {
            health_status: health,
            key_findings,
            priority_recommendations,
            score_breakdown,
        };
        new_report
    }

    fn apply_category_filters(
        report: &ClusterReport,
        filters: &[String],
        max_recommendations: Option<usize>,
    ) -> ClusterReport {
        let lower: Vec<String> = filters.iter().map(|s| s.to_lowercase()).collect();
        let mut new_report = report.clone();
        // Keep only inspection modules that have issues matching the category filter; recalc scores and summary.
        new_report.inspections = report
            .inspections
            .iter()
            .filter_map(|ins| {
                let mut ins_clone = ins.clone();
                ins_clone.summary.issues = ins
                    .summary
                    .issues
                    .iter()
                    .filter(|iss| {
                        lower
                            .iter()
                            .any(|f| iss.category.to_lowercase().contains(f))
                    })
                    .cloned()
                    .collect();

                if ins_clone.summary.issues.is_empty() {
                    return None;
                }

                // Keep checks list unchanged; overall_score remains per-module to avoid misleading stats.

                // Re-aggregate summary counts; checks counts stay as original.
                ins_clone.summary.total_checks = ins.summary.total_checks;
                ins_clone.summary.passed_checks = ins.summary.passed_checks;
                ins_clone.summary.warning_checks = ins.summary.warning_checks;
                ins_clone.summary.critical_checks = ins.summary.critical_checks;
                ins_clone.summary.error_checks = ins.summary.error_checks;
                Some(ins_clone)
            })
            .collect();

        // Rebuild executive summary from remaining modules.
        let engine = ScoringEngine::new();
        let overall = engine.calculate_weighted_score(&new_report.inspections);
        let health = engine.get_health_status(overall);
        let score_breakdown_details = engine.generate_score_breakdown(&new_report.inspections);
        let mut score_breakdown: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        for (k, v) in score_breakdown_details.into_iter() {
            score_breakdown.insert(k, v.score);
        }

        let max_r = max_recommendations.unwrap_or(DEFAULT_MAX_RECOMMENDATIONS);
        let key_findings = Self::build_aggregated_findings_error_only(&new_report);
        let priority_recommendations = Self::build_aggregated_recommendations(&new_report, max_r);

        new_report.overall_score = overall;
        new_report.executive_summary = ExecutiveSummary {
            health_status: health,
            key_findings,
            priority_recommendations,
            score_breakdown,
        };

        new_report
    }

    /// Build aggregated key findings from Critical issues: group by rule_id when present, else (category, recommendation).
    /// Output one line per group: code + short title + doc link + count + affected resources (or plain description/rec).
    #[allow(dead_code)]
    fn build_aggregated_findings(report: &ClusterReport, max_items: usize) -> Vec<String> {
        fn severity_ord(s: &IssueSeverity) -> u8 {
            match s {
                IssueSeverity::Critical => 0,
                IssueSeverity::Warning => 1,
                IssueSeverity::Info => 2,
            }
        }
        type GroupKey = (Option<String>, String, String);
        let mut groups: HashMap<GroupKey, (IssueSeverity, String, String, Vec<String>)> =
            HashMap::new();
        for inspection in &report.inspections {
            for issue in &inspection.summary.issues {
                if issue.severity != IssueSeverity::Critical {
                    continue;
                }
                let key: GroupKey = if let Some(ref rid) = issue.rule_id {
                    (Some(rid.clone()), String::new(), String::new())
                } else {
                    (None, issue.category.clone(), issue.recommendation.clone())
                };
                let title = issue
                    .rule_id
                    .as_ref()
                    .and_then(|c| {
                        issue_codes::short_title(issue_codes::strip_prefix(c)).map(String::from)
                    })
                    .unwrap_or_else(|| issue.description.clone());
                let entry = groups.entry(key).or_insert_with(|| {
                    (
                        issue.severity.clone(),
                        title,
                        issue.recommendation.clone(),
                        Vec::new(),
                    )
                });
                if severity_ord(&issue.severity) < severity_ord(&entry.0) {
                    entry.0 = issue.severity.clone();
                    entry.1 = issue
                        .rule_id
                        .as_ref()
                        .and_then(|c| {
                            issue_codes::short_title(issue_codes::strip_prefix(c)).map(String::from)
                        })
                        .unwrap_or_else(|| issue.description.clone());
                    entry.2 = issue.recommendation.clone();
                }
                if let Some(r) = &issue.resource {
                    entry.3.push(r.clone());
                }
            }
        }
        #[allow(clippy::type_complexity)]
        let mut rows: Vec<(IssueSeverity, Option<String>, String, String, Vec<String>)> = groups
            .into_iter()
            .map(|((rid, _cat, _rec), (sev, title, rec, resources))| {
                (sev, rid, title, rec, resources)
            })
            .collect();
        rows.sort_by(|a, b| {
            let sev_order = |s: &IssueSeverity| match s {
                IssueSeverity::Critical => 0,
                IssueSeverity::Warning => 1,
                IssueSeverity::Info => 2,
            };
            sev_order(&a.0)
                .cmp(&sev_order(&b.0))
                .then_with(|| b.4.len().cmp(&a.4.len()))
        });
        rows.truncate(max_items);
        rows.into_iter()
            .map(|(sev, rule_id, title, rec, resources)| {
                let severity_label = match sev {
                    IssueSeverity::Critical => "Critical",
                    IssueSeverity::Warning => "Warning",
                    IssueSeverity::Info => "Info",
                };
                let n = resources.len();
                let resource_list = format_affected_resources(&resources);
                if let Some(ref code) = rule_id {
                    if resource_list.is_empty() {
                        format!(
                            "[{}] **{}** {} ({}).",
                            severity_label,
                            display_issue_code(code),
                            title,
                            n
                        )
                    } else {
                        format!(
                            "[{}] **{}** {} ({}). Affected: {}",
                            severity_label,
                            display_issue_code(code),
                            title,
                            n,
                            resource_list
                        )
                    }
                } else if resource_list.is_empty() {
                    format!("[{}] {}: Recommendation: {}", severity_label, title, rec)
                } else {
                    format!(
                        "[{}] {} ({} issues): {}. Affected: {}. Recommendation: {}",
                        severity_label, title, n, title, resource_list, rec
                    )
                }
            })
            .collect()
    }

    /// Aggregated key findings for executive summary: error (Critical) level only, no limit.
    fn build_aggregated_findings_error_only(report: &ClusterReport) -> Vec<String> {
        let mut rows = Vec::new();
        type GroupKey = (Option<String>, String, String);
        let mut groups: HashMap<GroupKey, (String, String, Vec<String>)> = HashMap::new();
        for inspection in &report.inspections {
            for issue in &inspection.summary.issues {
                if issue.severity != IssueSeverity::Critical {
                    continue;
                }
                let key: GroupKey = if let Some(ref rid) = issue.rule_id {
                    (Some(rid.clone()), String::new(), String::new())
                } else {
                    (None, issue.category.clone(), issue.recommendation.clone())
                };
                let title = issue
                    .rule_id
                    .as_ref()
                    .and_then(|c| {
                        issue_codes::short_title(issue_codes::strip_prefix(c)).map(String::from)
                    })
                    .unwrap_or_else(|| issue.description.clone());
                let entry = groups
                    .entry(key)
                    .or_insert_with(|| (title, issue.recommendation.clone(), Vec::new()));
                if let Some(r) = &issue.resource {
                    entry.2.push(r.clone());
                }
            }
        }
        let mut rows_vec: Vec<_> = groups
            .into_iter()
            .map(|((rid, _cat, _rec), (title, rec, resources))| (rid, title, rec, resources))
            .collect();
        rows_vec.sort_by_key(|r| std::cmp::Reverse(r.3.len()));
        for (rule_id, title, rec, resources) in rows_vec {
            let n = resources.len();
            let resource_list = format_affected_resources(&resources);
            if let Some(ref code) = rule_id {
                if resource_list.is_empty() {
                    rows.push(format!(
                        "[error] **{}** {} ({}).",
                        display_issue_code(code),
                        title,
                        n
                    ));
                } else {
                    rows.push(format!(
                        "[error] **{}** {} ({}). Affected: {}",
                        display_issue_code(code),
                        title,
                        n,
                        resource_list
                    ));
                }
            } else if resource_list.is_empty() {
                rows.push(format!("[error] {}: Recommendation: {}", title, rec));
            } else {
                rows.push(format!(
                    "[error] {} ({} issues): {}. Affected: {}. Recommendation: {}",
                    title, n, title, resource_list, rec
                ));
            }
        }
        rows
    }

    /// Key findings as table rows (error/Critical only): one row per resource (resource, code_link, title).
    /// Issue Code is rendered as a link to the doc; no separate Doc column.
    #[allow(dead_code)]
    fn build_key_findings_table_rows(report: &ClusterReport) -> Vec<(String, String, String)> {
        type GroupKey = (Option<String>, String, String);
        let mut groups: HashMap<GroupKey, (String, String, Vec<String>)> = HashMap::new();
        for inspection in &report.inspections {
            for issue in &inspection.summary.issues {
                if issue.severity != IssueSeverity::Critical {
                    continue;
                }
                let key: GroupKey = if let Some(ref rid) = issue.rule_id {
                    (Some(rid.clone()), String::new(), String::new())
                } else {
                    (None, issue.category.clone(), issue.recommendation.clone())
                };
                let title = issue
                    .rule_id
                    .as_ref()
                    .and_then(|c| {
                        issue_codes::short_title(issue_codes::strip_prefix(c)).map(String::from)
                    })
                    .unwrap_or_else(|| issue.description.clone());
                let entry = groups
                    .entry(key)
                    .or_insert_with(|| (title, issue.recommendation.clone(), Vec::new()));
                if let Some(r) = &issue.resource {
                    entry.2.push(r.clone());
                }
            }
        }
        let mut out: Vec<(String, String, String)> = Vec::new();
        for ((rid, _cat, _), (title, _rec, resources)) in groups {
            let code_link = code_cell(rid.as_deref());
            if resources.is_empty() {
                out.push(("-".to_string(), code_link, title));
            } else {
                for r in resources {
                    out.push((r, code_link.clone(), title.clone()));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        out
    }

    /// Group issues by severity; within severity, group by rule_id when present, else by (category, recommendation).
    /// Each group yields (rule_id, title, recommendation, resources). Title is short_title(code) or first description.
    #[allow(clippy::type_complexity)]
    fn group_issues_by_severity_and_type(
        issues: &[Issue],
        lang: Lang,
    ) -> HashMap<IssueSeverity, Vec<(Option<String>, String, String, Vec<String>)>> {
        // Key: when rule_id present use (Some(rule_id), "", ""); else (None, category, recommendation)
        type Key = (Option<String>, String, String);
        #[allow(clippy::type_complexity)]
        let mut by_sev: HashMap<
            IssueSeverity,
            HashMap<Key, (String, String, Vec<String>)>,
        > = HashMap::new();
        for issue in issues {
            let key: Key = if let Some(ref rid) = issue.rule_id {
                (Some(rid.clone()), String::new(), String::new())
            } else {
                (None, issue.category.clone(), issue.recommendation.clone())
            };
            let entry = by_sev
                .entry(issue.severity.clone())
                .or_default()
                .entry(key)
                .or_insert_with(|| {
                    let title = issue
                        .rule_id
                        .as_ref()
                        .and_then(|c| issue_short_title(lang, c))
                        .unwrap_or_else(|| issue.description.clone());
                    (title, issue.recommendation.clone(), Vec::new())
                });
            if let Some(r) = &issue.resource {
                entry.2.push(r.clone());
            }
        }
        by_sev
            .into_iter()
            .map(|(sev, groups)| {
                let vec: Vec<_> = groups
                    .into_iter()
                    .map(|(k, (title, rec, resources))| (k.0, title, rec, resources))
                    .collect();
                (sev, vec)
            })
            .collect()
    }

    /// Build priority recommendations from error (Critical) issues only; dedup by text, sort by count (desc), take top N.
    fn build_aggregated_recommendations(report: &ClusterReport, max_items: usize) -> Vec<String> {
        let mut rec_counts: HashMap<String, usize> = HashMap::new();
        for inspection in &report.inspections {
            for issue in &inspection.summary.issues {
                if issue.severity == IssueSeverity::Critical {
                    *rec_counts.entry(issue.recommendation.clone()).or_insert(0) += 1;
                }
            }
        }
        let mut rows: Vec<(String, usize)> = rec_counts.into_iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        rows.truncate(max_items);
        rows.into_iter().map(|(rec, _)| rec).collect()
    }

    #[allow(dead_code)]
    fn build_statistics_section(&self, report: &ClusterReport) -> String {
        use std::collections::HashMap;

        let mut total_checks: u32 = 0;
        let mut severity_counts: HashMap<IssueSeverity, u32> = HashMap::new();
        let mut category_counts: HashMap<String, u32> = HashMap::new();
        let mut best_module: Option<(&String, f64)> = None;
        let mut worst_module: Option<(&String, f64)> = None;

        for inspection in &report.inspections {
            total_checks += inspection.summary.total_checks;

            let score = inspection.overall_score;
            match best_module {
                Some((_, best_score)) if score > best_score => {
                    best_module = Some((&inspection.inspection_type, score))
                }
                None => best_module = Some((&inspection.inspection_type, score)),
                _ => {}
            }
            match worst_module {
                Some((_, worst_score)) if score < worst_score => {
                    worst_module = Some((&inspection.inspection_type, score))
                }
                None => worst_module = Some((&inspection.inspection_type, score)),
                _ => {}
            }

            for issue in &inspection.summary.issues {
                *severity_counts.entry(issue.severity.clone()).or_insert(0) += 1;
                *category_counts.entry(issue.category.clone()).or_insert(0) += 1;
            }
        }

        let total_issues: u32 = severity_counts.values().sum();
        let mut content = String::new();
        content.push_str(self.tr().statistics_title);
        content.push_str(self.tr().metric_value_header);
        content.push_str("|--------|-------|\n");
        content.push_str(&crate::tr_fmt!(
            self,
            modules_checked_label,
            report.inspections.len()
        ));
        content.push_str(&crate::tr_fmt!(self, total_checks_label, total_checks));
        content.push_str(&crate::tr_fmt!(self, total_issues_label, total_issues));
        content.push_str(&crate::tr_fmt!(
            self,
            distinct_categories_label,
            category_counts.len()
        ));

        if total_issues > 0 {
            content.push_str(self.tr().severity_count_ratio_header);
            content.push_str("|----------|-------|-------|\n");
            let severities = [
                IssueSeverity::Critical,
                IssueSeverity::Warning,
                IssueSeverity::Info,
            ];
            for severity in &severities {
                if let Some(count) = severity_counts.get(severity) {
                    let label = self.severity_label(severity);
                    content.push_str(&format!(
                        "| {} | {} | {:.1}% |\n",
                        label,
                        count,
                        (*count as f64 / total_issues as f64) * 100.0
                    ));
                }
            }
            content.push('\n');
        }

        if !category_counts.is_empty() {
            let mut top_categories: Vec<(String, u32)> = category_counts.into_iter().collect();
            top_categories.sort_by_key(|r| std::cmp::Reverse(r.1));
            top_categories.truncate(5);
            content.push_str(self.tr().top_categories_title);
            for (category, count) in top_categories {
                content.push_str(&crate::tr_fmt!(
                    self,
                    top_cat_item_fmt,
                    self.lang.category_name(&category),
                    count
                ));
            }
            content.push('\n');
        }

        if let Some((module, score)) = best_module {
            content.push_str(&crate::tr_fmt!(
                self,
                best_module_fmt,
                self.lang.inspection_type_name(module),
                format!("{:.1}", score)
            ));
        }
        if let Some((module, score)) = worst_module {
            content.push_str(&crate::tr_fmt!(
                self,
                worst_module_fmt,
                self.lang.inspection_type_name(module),
                format!("{:.1}", score)
            ));
        }

        content
    }

    #[allow(dead_code)]
    fn node_inspection_status(n: &NodeInspectionResult) -> &'static str {
        let has_error = n.resources.status == "error"
            || n.services.status == "error"
            || n.security.status == "error"
            || n.kernel.status == "error";
        let has_warning = n.resources.status == "warning"
            || n.services.status == "warning"
            || n.security.status == "warning"
            || n.kernel.status == "warning";
        if has_error {
            "error"
        } else if has_warning || n.issue_count > 0 {
            "warning"
        } else {
            "ok"
        }
    }

    /// Renders Node Inspection section: Summary table + Node General Information + Node resources / services / security / kernel / certificates tables.
    fn format_node_inspection_section(&self, report: &ClusterReport) -> String {
        let nodes = report.node_inspection_results.as_deref().unwrap_or(&[]);
        let node_address_map: HashMap<String, String> = report
            .cluster_overview
            .as_ref()
            .and_then(|o| o.node_list.as_ref())
            .map(|list| {
                list.iter()
                    .filter_map(|r| r.node_address.as_ref().map(|a| (r.name.clone(), a.clone())))
                    .collect()
            })
            .unwrap_or_default();

        let node_api_os_kernel: HashMap<String, (Option<String>, Option<String>)> = report
            .cluster_overview
            .as_ref()
            .and_then(|o| o.node_list.as_ref())
            .map(|list| {
                list.iter()
                    .map(|r| {
                        (
                            r.name.clone(),
                            (r.os_image.clone(), r.kernel_version.clone()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let _node_api_runtime: HashMap<String, String> = report
            .cluster_overview
            .as_ref()
            .and_then(|o| o.node_list.as_ref())
            .map(|list| {
                list.iter()
                    .filter_map(|r| {
                        r.container_runtime_version
                            .as_ref()
                            .filter(|s| !s.is_empty())
                            .map(|v| (r.name.clone(), v.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Node Status (Ready/NotReady/Unknown) from node_conditions or node_list.ready (unused when Node services table is service×node)
        let _node_status: HashMap<String, &'static str> = report
            .cluster_overview
            .as_ref()
            .and_then(|o| o.node_conditions.as_ref())
            .map(|rows| {
                rows.iter()
                    .map(|r| {
                        let s = match r.ready.as_str() {
                            "True" => "Ready",
                            "False" => "NotReady",
                            _ => "Unknown",
                        };
                        (r.node_name.clone(), s)
                    })
                    .collect()
            })
            .or_else(|| {
                report
                    .cluster_overview
                    .as_ref()
                    .and_then(|o| o.node_list.as_ref())
                    .map(|list| {
                        list.iter()
                            .map(|r| (r.name.clone(), if r.ready { "Ready" } else { "NotReady" }))
                            .collect()
                    })
            })
            .unwrap_or_default();

        let mut out = String::new();
        out.push_str(self.tr().node_inspection_title);
        out.push_str(self.tr().node_inspection_desc);

        // (0) Node General Information: Node | OS Version | IP Address | Kernel Version | Uptime | Collection time
        out.push_str(self.tr().node_general_info_title);
        out.push_str(self.tr().node_general_info_header);
        out.push_str(
            "|------|-------------|------------|----------------|--------|------------------|\n",
        );
        for n in nodes {
            let (api_os, api_kernel) = node_api_os_kernel
                .get(&n.node_name)
                .cloned()
                .unwrap_or((None, None));
            let os_ver = api_os.as_deref().or(n.os_version.as_deref()).unwrap_or("-");
            let ip = node_address_map
                .get(&n.node_name)
                .map(|s| s.as_str())
                .unwrap_or("-");
            let kernel = api_kernel
                .as_deref()
                .or(n.kernel_version.as_deref())
                .unwrap_or("-");
            let uptime = n.uptime.as_deref().unwrap_or("-");
            let timestamp = if n.timestamp.is_empty() {
                "-"
            } else {
                n.timestamp.as_str()
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                n.node_name, os_ver, ip, kernel, uptime, timestamp
            ));
        }
        out.push('\n');

        // (1) Node resources: CPU, Mem, Swap, Load (CPU Used/CPU % placeholder "-" until script provides)
        out.push_str(self.tr().node_resources_title);
        out.push_str(self.tr().node_resources_header);
        out.push_str("|------|-------------|----------|-------|----------------|---------------|-------|----------------|---------------|-------|---------------------|\n");
        for n in nodes {
            let cpu = n
                .resources
                .cpu_cores
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let cpu_used = n
                .resources
                .cpu_used
                .map(|u| format!("{:.2}", u))
                .unwrap_or_else(|| "-".to_string());
            let cpu_pct = n
                .resources
                .cpu_used_pct
                .map(|p| format!("{:.1}%", p))
                .unwrap_or_else(|| "-".to_string());
            let mem_total_g = n
                .resources
                .memory_total_mib
                .map(|m| format!("{:.1}", m as f64 / 1024.0))
                .unwrap_or_else(|| "-".to_string());
            let mem_used_g = n
                .resources
                .memory_used_mib
                .map(|m| format!("{:.1}", m as f64 / 1024.0))
                .unwrap_or_else(|| "-".to_string());
            let mem_pct = n
                .resources
                .memory_used_pct
                .map(|p| format!("{:.1}%", p))
                .unwrap_or_else(|| "-".to_string());
            let swap_total_g = n
                .resources
                .swap_total_g
                .map(|g| format!("{:.2}", g))
                .unwrap_or_else(|| "-".to_string());
            let swap_used_g = n
                .resources
                .swap_used_g
                .map(|g| format!("{:.2}", g))
                .unwrap_or_else(|| "-".to_string());
            let swap_pct = n
                .resources
                .swap_used_pct
                .map(|p| format!("{:.1}%", p))
                .unwrap_or_else(|| "-".to_string());
            let load_1m = n.resources.load_1m.as_deref().unwrap_or("-");
            let load_5m = n.resources.load_5m.as_deref().unwrap_or("-");
            let load_15m = n.resources.load_15m.as_deref().unwrap_or("-");
            let load_merged = format!("{}, {}, {}", load_1m, load_5m, load_15m);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                n.node_name,
                cpu,
                cpu_used,
                cpu_pct,
                mem_total_g,
                mem_used_g,
                mem_pct,
                swap_total_g,
                swap_used_g,
                swap_pct,
                load_merged
            ));
        }
        out.push('\n');

        // (1a) Node disk usage: per-node mount rows grouped by disk, sorted shallow-first;
        //      status thresholds Info (<80%), Warning (80–90%), Critical (>=90%)
        out.push_str(self.tr().node_disk_usage_title);
        out.push_str(self.tr().node_disk_usage_desc);
        out.push_str(self.tr().node_disk_usage_header);
        out.push_str("|------|-------------|--------|--------|------------|------------|--------|--------|\n");
        let node_004_link = "004".to_string();
        let node_005_link = "005".to_string();
        for n in nodes {
            let disks = n.node_disks.as_deref().unwrap_or(&[]);
            if disks.is_empty() {
                out.push_str(&format!(
                    "| {} | - | - | - | - | - | - | - |\n",
                    n.node_name
                ));
                continue;
            }
            // 按磁盘分组展示：分区归一化为物理磁盘，同一设备同容量的绑定挂载只保留最浅挂载点
            let rows = build_disk_rows(disks);
            for (mp, device, fstype, total_g, used_g, used_pct) in &rows {
                let total_g = total_g
                    .map(|g| format!("{:.1}", g))
                    .unwrap_or_else(|| "-".to_string());
                let used_g = used_g
                    .map(|g| format!("{:.1}", g))
                    .unwrap_or_else(|| "-".to_string());
                let used_pct_str = used_pct
                    .map(|p| format!("{:.1}%", p))
                    .unwrap_or_else(|| "-".to_string());
                let status = match used_pct {
                    Some(p) if *p >= 90.0 => format!(
                        "{} {}",
                        self.severity_label(&IssueSeverity::Critical),
                        node_005_link
                    ),
                    Some(p) if *p >= 80.0 => format!(
                        "{} {}",
                        self.severity_label(&IssueSeverity::Warning),
                        node_004_link
                    ),
                    Some(_) => self.severity_label(&IssueSeverity::Info).to_string(),
                    None => "-".to_string(),
                };
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                    n.node_name,
                    if mp.is_empty() {
                        "-".to_string()
                    } else {
                        host_path_display(mp)
                    },
                    if device.is_empty() {
                        "-".to_string()
                    } else {
                        device.clone()
                    },
                    if fstype.is_empty() {
                        "-".to_string()
                    } else {
                        fstype.clone()
                    },
                    total_g,
                    used_g,
                    used_pct_str,
                    status
                ));
            }
        }
        out.push('\n');

        // (1b) Node container state counts: Node | Running | Waiting | Exited
        out.push_str(self.tr().node_container_state_title);
        out.push_str(self.tr().node_container_state_header);
        out.push_str("|------|---------|---------|--------|\n");
        for n in nodes {
            let counts = n.container_state_counts.as_ref();
            let running = counts.and_then(|c| c.get("running")).copied().unwrap_or(0);
            let waiting = counts.and_then(|c| c.get("waiting")).copied().unwrap_or(0);
            let exited = counts.and_then(|c| c.get("exited")).copied().unwrap_or(0);
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                n.node_name, running, waiting, exited
            ));
        }
        out.push('\n');

        // (2) Node component and service status: Node | Kubelet | Container runtime | NTP synced | Journald | Crontab
        out.push_str(self.tr().node_service_status_title);
        out.push_str(self.tr().node_service_status_header);
        out.push_str("|------|--------|-------------------|------------|----------|----------|\n");
        for n in nodes {
            let kubelet = self.service_status_label(n.services.kubelet_running);
            let runtime = self.service_status_label(n.services.container_runtime_running);
            let ntp = self.service_status_label(n.services.ntp_synced);
            let journald = self.service_status_label(n.services.journald_active);
            let crontab = self.service_status_label(n.services.crontab_present);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                n.node_name, kubelet, runtime, ntp, journald, crontab
            ));
        }
        out.push('\n');

        // (3) Node security and kernel modules: Node | SELinux | Firewalld | IPVS | br_netfilter | overlay | nf_conntrack
        out.push_str(self.tr().node_security_title);
        out.push_str(self.tr().node_security_desc);
        out.push_str(self.tr().node_security_header);
        out.push_str(
            "|------|---------|------------|------|--------------|---------|---------------|\n",
        );
        for n in nodes {
            let fw = n
                .security
                .firewalld_active
                .map(|b| {
                    if b {
                        self.tr().firewalld_active
                    } else {
                        self.tr().firewalld_inactive
                    }
                })
                .unwrap_or("-");
            let ipvs = self.yes_no_label(n.security.ipvs_loaded);
            let br_netfilter = self.yes_no_label(n.security.br_netfilter_loaded);
            let overlay = self.yes_no_label(n.security.overlay_loaded);
            let nf_conntrack = self.yes_no_label(n.security.nf_conntrack_loaded);
            let se = match n.security.selinux.as_deref() {
                Some(s) => self.lang.selinux_mode(s),
                None => Cow::Borrowed("-"),
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                n.node_name, se, fw, ipvs, br_netfilter, overlay, nf_conntrack
            ));
        }
        out.push('\n');

        // (3b) Node network and stability: Node | Conntrack usage % | Inode usage % | OOM count | FD (open/max) | Zombie count
        out.push_str(self.tr().node_network_title);
        out.push_str(self.tr().node_network_desc);
        out.push_str(self.tr().node_network_header);
        out.push_str("|------|-------------------|---------------|-----------|---------------|---------------|\n");
        for n in nodes {
            let conntrack_pct = match (n.security.nf_conntrack_count, n.security.nf_conntrack_max) {
                (Some(c), Some(m)) if m > 0 => format!("{:.1}%", (c as f64 / m as f64) * 100.0),
                _ => "-".to_string(),
            };
            let inode_pct = n
                .stability
                .as_ref()
                .and_then(|s| s.inode_used_pct)
                .map(|p| format!("{:.1}%", p))
                .unwrap_or_else(|| "-".to_string());
            let oom = n
                .stability
                .as_ref()
                .and_then(|s| s.oom_kill_count)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let fd = match (
                n.stability.as_ref().and_then(|s| s.file_nr_open),
                n.stability.as_ref().and_then(|s| s.file_nr_max),
            ) {
                (Some(o), Some(m)) => format!("{}/{}", o, m),
                _ => "-".to_string(),
            };
            let zombie = n.zombie_count.unwrap_or(0);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                n.node_name, conntrack_pct, inode_pct, oom, fd, zombie
            ));
        }
        out.push('\n');

        // (4) Node kernel parameters: Node | net.ipv4.ip_forward | vm.swappiness | net.core.somaxconn
        out.push_str(self.tr().node_kernel_title);
        out.push_str(self.tr().node_kernel_desc);
        out.push_str(self.tr().node_kernel_header);
        out.push_str("|------|---------------------|--------------|--------------------|\n");
        for n in nodes {
            let fwd = n.kernel.net_ipv4_ip_forward.as_deref().unwrap_or("-");
            let sw = n.kernel.vm_swappiness.as_deref().unwrap_or("-");
            let somax = n.kernel.net_core_somaxconn.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                n.node_name, fwd, sw, somax
            ));
        }
        out.push('\n');

        // (5) Node Certificate Status: Node | Path | Expired | Expiration Date (node local) | Days to Expiry | Level | Issue Code
        out.push_str(self.tr().node_certificate_title);
        out.push_str(self.tr().node_certificate_header);
        out.push_str("|------|------|---------|------------------------------|----------------|-------|------------|\n");
        for n in nodes {
            let certs = n.node_certificates.as_deref().unwrap_or(&[]);
            if certs.is_empty() {
                out.push_str(&format!("| {} | - | - | - | - | - | - |\n", n.node_name));
            } else {
                for c in certs {
                    let expired = if c.status == "Expired" {
                        self.tr().yes_label
                    } else {
                        self.tr().no_label
                    };
                    let (level, issue_code) = if c.days_remaining < 0 {
                        (self.severity_label(&IssueSeverity::Critical), "B03")
                    } else if c.days_remaining <= 30 {
                        (self.severity_label(&IssueSeverity::Warning), "B02")
                    } else {
                        (self.severity_label(&IssueSeverity::Info), "B02")
                    };
                    out.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} | {} |\n",
                        n.node_name,
                        host_path_display(&c.path),
                        expired,
                        c.expiration_date,
                        c.days_remaining,
                        level,
                        issue_code
                    ));
                }
            }
        }
        out.push('\n');

        out
    }

    fn generate_main_report(
        &self,
        report: &ClusterReport,
        max_recommendations: Option<usize>,
        check_level_filter: Option<CheckLevelFilter>,
    ) -> Result<String> {
        let _max_r = max_recommendations.unwrap_or(DEFAULT_MAX_RECOMMENDATIONS);
        let check_filter = check_level_filter.unwrap_or(CheckLevelFilter::Only(vec![
            CheckStatus::Warning,
            CheckStatus::Critical,
            CheckStatus::Error,
        ]));
        let mut content = String::new();

        // Header (title includes the cluster name; the generic kubeadm/minikube
        // name "kubernetes" is displayed as "default" instead)
        content.push_str(&crate::tr_fmt!(
            self,
            title_fmt,
            self.cluster_display_name(report)
        ));

        content.push_str(&crate::tr_fmt!(self, report_id_label, report.report_id));

        content.push_str(&crate::tr_fmt!(
            self,
            cluster_label,
            self.cluster_display_name(report)
        ));

        let generated_at = report.display_timestamp.clone().unwrap_or_else(|| {
            // Fallback to China Standard Time (CST, UTC+8) instead of UTC.
            let cst =
                chrono::FixedOffset::east_opt(8 * 3600).expect("UTC+8 is a valid fixed offset");
            report
                .timestamp
                .with_timezone(&cst)
                .format("%Y-%m-%d %H:%M:%S CST")
                .to_string()
        });
        content.push_str(&crate::tr_fmt!(self, generated_at_label, generated_at));

        // Cluster Overview: always output section (placeholder if no data); core metrics in table
        content.push_str(self.tr().cluster_overview_title);
        if let Some(ref overview) = report.cluster_overview {
            content.push_str(self.tr().metric_value_header);
            content.push_str("|--------|-------|\n");
            if let Some(ref v) = overview.cluster_version {
                content.push_str(&crate::tr_fmt!(self, cluster_version_label, v));
            }
            content.push_str(&crate::tr_fmt!(self, node_count_label, overview.node_count));
            content.push_str(&crate::tr_fmt!(
                self,
                ready_nodes_label,
                overview.ready_node_count
            ));
            if let Some(pc) = overview.pod_count {
                content.push_str(&crate::tr_fmt!(self, pod_count_label, pc));
            }
            if let Some(nc) = overview.namespace_count {
                content.push_str(&crate::tr_fmt!(self, namespace_count_label, nc));
            }
            if let Some(age) = overview.cluster_age_days {
                content.push_str(&crate::tr_fmt!(self, cluster_age_label, age));
            }
            if let Some(ref node_list) = overview.node_list {
                let runtimes: std::collections::HashSet<&str> = node_list
                    .iter()
                    .filter_map(|r| r.container_runtime_version.as_deref())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !runtimes.is_empty() {
                    let rt_str: Vec<&str> = runtimes.into_iter().collect();
                    content.push_str(&crate::tr_fmt!(
                        self,
                        container_runtime_label,
                        rt_str.join(", ")
                    ));
                }
            }
            let health_emoji = match report.executive_summary.health_status {
                HealthStatus::Excellent => "🟢",
                HealthStatus::Good => "🟡",
                HealthStatus::Fair => "🟠",
                HealthStatus::Poor => "🔴",
                HealthStatus::Critical => "🚨",
            };
            let health_text = self.health_label(&report.executive_summary.health_status);
            content.push_str(&crate::tr_fmt!(
                self,
                overall_health_fmt,
                health_emoji,
                health_text,
                format!("{:.1}", report.overall_score)
            ));
            content.push('\n');
            if let Some(ref conds) = overview.node_conditions {
                if !conds.is_empty() {
                    content.push_str(self.tr().node_conditions_title);
                    content.push_str(self.tr().node_conditions_header);
                    content.push_str(
                        "|------|-------|----------------|--------------|-------------|\n",
                    );
                    for r in conds {
                        content.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            r.node_name,
                            self.lang.condition_value(&r.ready),
                            self.lang.condition_value(&r.memory_pressure),
                            self.lang.condition_value(&r.disk_pressure),
                            self.lang.condition_value(&r.pid_pressure)
                        ));
                    }
                    content.push('\n');
                }
            }
            // Workload summary
            if let Some(ref wl) = overview.workload_summary {
                content.push_str(self.tr().workload_title);
                content.push_str(self.tr().workload_header);
                content.push_str("|------------|-------|-------|\n");
                content.push_str(&format!(
                    "| Deployment | {} | {} |\n",
                    wl.deployments_total, wl.deployments_ready
                ));
                content.push_str(&format!(
                    "| StatefulSet | {} | {} |\n",
                    wl.statefulsets_total, wl.statefulsets_ready
                ));
                content.push_str(&format!(
                    "| DaemonSet | {} | {} |\n\n",
                    wl.daemonsets_total, wl.daemonsets_ready
                ));
            }
            // Storage summary
            if let Some(ref st) = overview.storage_summary {
                content.push_str(self.tr().storage_title);
                content.push_str(self.tr().metric_value_header);
                content.push_str("|--------|-------|\n");
                content.push_str(&crate::tr_fmt!(self, pv_total_label, st.pv_total));
                content.push_str(&crate::tr_fmt!(self, pvc_total_label, st.pvc_total));
                content.push_str(&crate::tr_fmt!(self, pvc_bound_label, st.pvc_bound));
                content.push_str(&crate::tr_fmt!(
                    self,
                    storage_class_count_label,
                    st.storage_class_count
                ));
                content.push_str(&crate::tr_fmt!(
                    self,
                    default_storage_class_label,
                    if st.has_default_storage_class {
                        self.tr().yes_label
                    } else {
                        self.tr().no_label
                    }
                ));
            }
            // Container resource usage: top 20 high usage (usage/limit >= 80%); shown only when metrics available
            if overview.metrics_available == Some(true) {
                if let Some(ref rows) = overview.container_usage_notable {
                    if !rows.is_empty() {
                        content.push_str(self.tr().container_usage_title);
                        content.push_str(self.tr().container_usage_desc);
                        content.push_str(self.tr().container_usage_header);
                        content.push_str("|-----------|-----|-----------|--------------|-----------------|---------------|---------------|------------------|----------------|------|\n");
                        for r in rows {
                            let note = self.lang.container_note(&r.notable_reason);
                            content.push_str(&format!(
                                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                                r.namespace,
                                r.pod_name,
                                r.container_name,
                                r.cpu_used_m,
                                r.cpu_request_m,
                                r.cpu_limit_m,
                                r.mem_used_mib,
                                r.mem_request_mib,
                                r.mem_limit_mib,
                                note
                            ));
                        }
                        content.push('\n');
                    }
                }
            }
        } else {
            content.push_str(self.tr().overview_unavailable);
        }

        // Node Inspection (from DaemonSet): Summary + category tables, or placeholder when no data
        match report.node_inspection_results.as_deref() {
            Some(nodes) if !nodes.is_empty() => {
                content.push_str(&self.format_node_inspection_section(report));
            }
            _ => {
                content.push_str(self.tr().node_inspection_title);
                content.push_str(self.tr().node_inspection_no_data);
            }
        }

        // Recent cluster events (Warning / Error only)
        if let Some(ref events) = report.recent_events {
            if !events.is_empty() {
                content.push_str(self.tr().events_title);
                content.push_str(self.tr().events_header);
                content.push_str("|-----------|--------|-------|--------|---------|----------|\n");
                for e in events {
                    let level = match e.event_type.as_str() {
                        "Error" => self.severity_label(&IssueSeverity::Critical),
                        "Warning" => self.severity_label(&IssueSeverity::Warning),
                        "Normal" => self.severity_label(&IssueSeverity::Info),
                        _ => e.event_type.as_str(),
                    };
                    content.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        e.namespace,
                        e.object_ref,
                        level,
                        e.reason,
                        truncate_string(&e.message, 60),
                        e.last_seen
                    ));
                }
                content.push('\n');
            }
        }

        // Database middleware (detected by container image) — 置于《详细结果》之前
        match report.db_middleware.as_deref() {
            Some(mw) if !mw.is_empty() => {
                content.push_str(self.tr().db_middleware_title);
                content.push_str(self.tr().db_middleware_desc);
                content.push_str(self.tr().db_middleware_header);
                content.push_str("|-----------|-------|------------|-------|---------|\n");
                for m in mw {
                    let ready = if m.ready {
                        self.lang.t("Yes", "是")
                    } else {
                        self.lang.t("No", "否")
                    };
                    content.push_str(&format!(
                        "| `{}` | `{}` | `{}` | {} | {} |\n",
                        m.namespace,
                        m.pod_name,
                        truncate_string(&m.image, 44),
                        ready,
                        m.restart_count
                    ));
                }
                content.push('\n');
            }
            _ => {
                content.push_str(self.tr().db_middleware_title);
                content.push_str(self.tr().db_middleware_none);
            }
        }

        // Detailed results grouped by Kubernetes resource object
        content.push_str(self.tr().detailed_results_title);

        // Check Results: first column = cluster resource object; filter by check level (default: exclude Pass)
        content.push_str(self.tr().check_results_title);
        content.push_str(self.tr().check_results_header);
        content.push_str("|----------|------------|--------|-------|----------|\n");
        const DETAILS_MAX_LEN: usize = 60;
        for inspection in &report.inspections {
            let resource = inspection_type_to_resource(&inspection.inspection_type);
            for check in &inspection.checks {
                let include = match &check_filter {
                    CheckLevelFilter::All => true,
                    CheckLevelFilter::Only(list) => list.contains(&check.status),
                };
                if !include {
                    continue;
                }
                let status_text = self.lang.check_status_text(&check.status);
                let details_str = check.details.as_deref().unwrap_or("-");
                let details_short = truncate_string(details_str, DETAILS_MAX_LEN);
                content.push_str(&format!(
                    "| {} | {} | {} | {:.1}/{:.1} | {} |\n",
                    resource,
                    self.lang.check_name(&check.name),
                    status_text,
                    check.score,
                    check.max_score,
                    details_short
                ));
            }
        }
        content.push('\n');

        // Namespace summary table (from Namespace inspection)
        if let Some(rows) = report
            .inspections
            .iter()
            .find_map(|i| i.namespace_summary_rows.as_ref().filter(|v| !v.is_empty()))
        {
            content.push_str(self.tr().namespace_summary_title);
            content.push_str(self.tr().namespace_summary_header);
            content.push_str(
                "|-----------|------|-------------|---------------|---------------|------------|\n",
            );
            for r in rows {
                content.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    r.name,
                    r.pod_count,
                    r.deployment_count,
                    if r.has_network_policy {
                        self.tr().yes_label
                    } else {
                        self.tr().no_label
                    },
                    if r.has_resource_quota {
                        self.tr().yes_label
                    } else {
                        self.tr().no_label
                    },
                    if r.has_limit_range {
                        self.tr().yes_label
                    } else {
                        self.tr().no_label
                    },
                ));
            }
            content.push('\n');
        }

        // Per-resource sections: only emit if at least one issue or one detail block (Pod container state table omitted)
        let by_resource = group_issues_by_resource(report);
        let cert_expiries = report.inspections.iter().find_map(|i| {
            i.certificate_expiries
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.as_slice())
        });

        for &resource in REPORT_RESOURCE_ORDER {
            let issues = by_resource
                .get(resource)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let has_cert_expiries = resource == "Certificate" && cert_expiries.is_some();
            if issues.is_empty() && !has_cert_expiries {
                continue;
            }
            let slug = slugify(resource);
            content.push_str(&format!("<a id=\"{}\"></a>\n\n", slug));
            content.push_str(&format!("### {}\n\n", resource));
            if has_cert_expiries {
                if let Some(expiries) = cert_expiries {
                    content.push_str(self.tr().tls_cert_expiry_title);
                    content.push_str(self.tr().tls_cert_header);
                    content.push_str("|--------------------------|---------|--------------|----------------|-------|------------|\n");
                    for row in expiries {
                        let expired = if row.days_until_expiry < 0 {
                            self.tr().yes_label
                        } else {
                            self.tr().no_label
                        };
                        let (level, code_link) = if row.days_until_expiry < 0 {
                            (
                                self.severity_label(&IssueSeverity::Critical),
                                String::from("B03"),
                            )
                        } else if row.days_until_expiry <= 30 {
                            (
                                self.severity_label(&IssueSeverity::Warning),
                                String::from("B02"),
                            )
                        } else {
                            (
                                self.severity_label(&IssueSeverity::Info),
                                String::from("B02"),
                            )
                        };
                        let secret_cell = format!("{}/{}", row.secret_namespace, row.secret_name);
                        content.push_str(&format!(
                            "| {} | {} | {} | {} | {} | {} |\n",
                            secret_cell,
                            expired,
                            row.expiry_utc,
                            row.days_until_expiry,
                            level,
                            code_link
                        ));
                    }
                    content.push('\n');
                }
            }
            if !issues.is_empty() {
                content.push_str(self.tr().issue_table_header);
                content.push_str("|----------|-------|------------|-------------|\n");
                let grouped = Self::group_issues_by_severity_and_type(issues, self.lang);
                let severity_to_level = |s: &IssueSeverity| self.severity_label(s);
                for sev in &[
                    IssueSeverity::Critical,
                    IssueSeverity::Warning,
                    IssueSeverity::Info,
                ] {
                    // Default: only Warning and Critical (exclude Info). With --check-level all, show Info too.
                    if matches!(sev, IssueSeverity::Info)
                        && !matches!(&check_filter, CheckLevelFilter::All)
                    {
                        continue;
                    }
                    let level = severity_to_level(sev);
                    if let Some(groups) = grouped.get(sev) {
                        for (rule_id, title, _rec, resources) in groups {
                            let code_link = code_cell(rule_id.as_deref());
                            if resources.is_empty() {
                                content.push_str(&format!(
                                    "| {} | {} | {} | {} |\n",
                                    resource, level, code_link, title
                                ));
                            } else {
                                for r in resources {
                                    content.push_str(&format!(
                                        "| `{}` | {} | {} | {} |\n",
                                        r, level, code_link, title
                                    ));
                                }
                            }
                        }
                    }
                }
                content.push('\n');
            }
            content.push_str("---\n\n");
        }

        // Footer
        content.push_str("---\n\n");
        content.push_str(self.tr().footer);

        Ok(content)
    }

    fn generate_summary_report(&self, report: &ClusterReport) -> Result<String> {
        let mut content = String::new();

        content.push_str(self.tr().summary_title);

        content.push_str(&crate::tr_fmt!(
            self,
            cluster_label,
            self.cluster_display_name(report)
        ));

        let generated_at = report.display_timestamp.clone().unwrap_or_else(|| {
            // Fallback to China Standard Time (CST, UTC+8) instead of UTC.
            let cst =
                chrono::FixedOffset::east_opt(8 * 3600).expect("UTC+8 is a valid fixed offset");
            report
                .timestamp
                .with_timezone(&cst)
                .format("%Y-%m-%d %H:%M:%S CST")
                .to_string()
        });
        content.push_str(&crate::tr_fmt!(self, generated_at_label, generated_at));

        // Group by 3 severities
        let mut critical_issues = Vec::new();
        let mut warning_issues = Vec::new();
        let mut info_issues = Vec::new();

        for inspection in &report.inspections {
            for issue in &inspection.summary.issues {
                match issue.severity {
                    IssueSeverity::Critical => critical_issues.push((inspection, issue)),
                    IssueSeverity::Warning => warning_issues.push((inspection, issue)),
                    IssueSeverity::Info => info_issues.push((inspection, issue)),
                }
            }
        }

        // Summary statistics
        content.push_str(self.tr().issue_statistics_title);
        content.push_str(self.tr().severity_count_ratio_header);
        content.push_str("|----------|-------|-------|\n");

        let total_issues = critical_issues.len() + warning_issues.len() + info_issues.len();

        if total_issues > 0 {
            content.push_str(&format!(
                "| {} | {} | {:.1}% |\n",
                self.severity_label(&IssueSeverity::Critical),
                critical_issues.len(),
                (critical_issues.len() as f64 / total_issues as f64) * 100.0
            ));
            content.push_str(&format!(
                "| {} | {} | {:.1}% |\n",
                self.severity_label(&IssueSeverity::Warning),
                warning_issues.len(),
                (warning_issues.len() as f64 / total_issues as f64) * 100.0
            ));
            content.push_str(&format!(
                "| {} | {} | {:.1}% |\n",
                self.severity_label(&IssueSeverity::Info),
                info_issues.len(),
                (info_issues.len() as f64 / total_issues as f64) * 100.0
            ));
        }
        content.push('\n');

        // Critical: one table
        let critical_flat: Vec<_> = critical_issues.iter().map(|(_, i)| (*i).clone()).collect();
        let critical_grouped = Self::group_issues_by_severity_and_type(&critical_flat, self.lang);

        if let Some(groups) = critical_grouped.get(&IssueSeverity::Critical) {
            content.push_str(self.tr().critical_issues_title);
            content.push_str(self.tr().immediate_action);
            content.push_str(self.tr().issue_table_header_no_level);
            content.push_str("|----------|------------|-------------|\n");
            for (rule_id, title, _rec, resources) in groups {
                let code_link = code_cell(rule_id.as_deref());
                if resources.is_empty() {
                    content.push_str(&format!("| - | {} | {} |\n", code_link, title));
                } else {
                    for r in resources {
                        content.push_str(&format!("| `{}` | {} | {} |\n", r, code_link, title));
                    }
                }
            }
            content.push('\n');
        }

        // Warning and Info: single "Other Issues" table
        if !warning_issues.is_empty() || !info_issues.is_empty() {
            content.push_str(self.tr().other_issues_title);
            content.push_str(self.tr().other_issues_header);
            content.push_str(
                "|------|----------|----------|-------|-----------------|----------------|\n",
            );

            let warning_groups = Self::group_issues_for_summary_table_with_code(&warning_issues);
            for (code, cat, rec, count, sample) in warning_groups {
                let sample_short = truncate_string(&sample, 40);
                content.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    code,
                    self.severity_label(&IssueSeverity::Warning),
                    self.lang.category_name(&cat),
                    count,
                    sample_short,
                    truncate_string(&rec, 50)
                ));
            }
            let info_groups = Self::group_issues_for_summary_table_with_code(&info_issues);
            for (code, cat, rec, count, sample) in info_groups {
                let sample_short = truncate_string(&sample, 40);
                content.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    code,
                    self.severity_label(&IssueSeverity::Info),
                    self.lang.category_name(&cat),
                    count,
                    sample_short,
                    truncate_string(&rec, 50)
                ));
            }
            content.push('\n');
        }

        // Recommendations by category: sort by issue count, show "N issues" per recommendation
        content.push_str(self.tr().recs_by_category_title);

        let mut category_rec_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();
        for inspection in &report.inspections {
            for issue in &inspection.summary.issues {
                let rec_map = category_rec_counts
                    .entry(issue.category.clone())
                    .or_default();
                *rec_map.entry(issue.recommendation.clone()).or_insert(0) += 1;
            }
        }
        let mut category_totals: Vec<(String, usize)> = category_rec_counts
            .iter()
            .map(|(cat, rec_map)| (cat.clone(), rec_map.values().sum()))
            .collect();
        category_totals.sort_by_key(|r| std::cmp::Reverse(r.1));

        for (category, _total) in category_totals {
            if let Some(rec_map) = category_rec_counts.get(&category) {
                let mut rec_list: Vec<(String, usize)> =
                    rec_map.iter().map(|(r, c)| (r.clone(), *c)).collect();
                rec_list.sort_by_key(|r| std::cmp::Reverse(r.1));
                content.push_str(&format!("### {}\n\n", self.lang.category_name(&category)));
                for (recommendation, count) in rec_list {
                    content.push_str(&crate::tr_fmt!(self, rec_count_fmt, recommendation, count));
                }
                content.push('\n');
            }
        }

        Ok(content)
    }

    /// Group issues by (category, recommendation), return (category, recommendation, count, sample_resource).
    #[allow(dead_code)]
    fn group_issues_for_summary_table(
        issues: &[(&InspectionResult, &Issue)],
    ) -> Vec<(String, String, usize, String)> {
        let mut groups: HashMap<(String, String), (usize, String)> = HashMap::new();
        for (_inspection, issue) in issues {
            let key = (issue.category.clone(), issue.recommendation.clone());
            let entry = groups.entry(key).or_insert((0, String::new()));
            entry.0 += 1;
            if entry.1.is_empty() {
                entry.1 = issue.resource.clone().unwrap_or_default();
            }
        }
        groups
            .into_iter()
            .map(|((cat, rec), (count, sample))| (cat, rec, count, sample))
            .collect()
    }

    /// Like group_issues_for_summary_table but includes issue code (rule_id or "-"). Returns (code, category, recommendation, count, sample).
    fn group_issues_for_summary_table_with_code(
        issues: &[(&InspectionResult, &Issue)],
    ) -> Vec<(String, String, String, usize, String)> {
        let mut groups: HashMap<(Option<String>, String, String), (usize, String)> = HashMap::new();
        for (_inspection, issue) in issues {
            let key = (
                issue.rule_id.clone(),
                issue.category.clone(),
                issue.recommendation.clone(),
            );
            let entry = groups.entry(key).or_insert((0, String::new()));
            entry.0 += 1;
            if entry.1.is_empty() {
                entry.1 = issue.resource.clone().unwrap_or_default();
            }
        }
        groups
            .into_iter()
            .map(|((code, cat, rec), (count, sample))| {
                let code_str = code.as_deref().unwrap_or("-").to_string();
                (code_str, cat, rec, count, sample)
            })
            .collect()
    }

    #[allow(dead_code)]
    fn format_inspection_result(&self, inspection: &InspectionResult) -> Result<String> {
        let mut content = String::new();

        let slug = slugify(&inspection.inspection_type);
        content.push_str(&format!("<a id=\"{}\"></a>\n\n", slug));
        content.push_str(&crate::tr_fmt!(
            self,
            inspection_score_title_fmt,
            self.lang.inspection_type_name(&inspection.inspection_type),
            format!("{:.1}", inspection.overall_score)
        ));

        // Summary
        content.push_str(&crate::tr_fmt!(
            self,
            check_items_fmt,
            inspection.summary.total_checks,
            inspection.summary.passed_checks,
            inspection.summary.warning_checks,
            inspection.summary.critical_checks,
            inspection.summary.error_checks
        ));

        // Check results
        content.push_str(self.tr().check_results_title_4);
        content.push_str(self.tr().check_results_header_no_resource);
        content.push_str("|------------|--------|-------|----------|\n");

        const DETAILS_MAX_LEN: usize = 60;
        for check in &inspection.checks {
            let status_text = self.lang.check_status_text(&check.status);
            let details_str = check.details.as_deref().unwrap_or("-");
            let details_short = truncate_string(details_str, DETAILS_MAX_LEN);

            content.push_str(&format!(
                "| {} | {} | {:.1}/{:.1} | {} |\n",
                self.lang.check_name(&check.name),
                status_text,
                check.score,
                check.max_score,
                details_short
            ));
        }
        content.push('\n');

        // TLS certificate expiry table (Certificates inspection only)
        if let Some(ref expiries) = inspection.certificate_expiries {
            if !expiries.is_empty() {
                content.push_str(self.tr().tls_cert_expiry_title);
                content.push_str(self.tr().tls_cert_header);
                content.push_str("|--------------------------|---------|--------------|----------------|-------|------------|\n");
                for row in expiries {
                    let expired = if row.days_until_expiry < 0 {
                        self.tr().yes_label
                    } else {
                        self.tr().no_label
                    };
                    let (level, code_link) = if row.days_until_expiry < 0 {
                        (
                            self.severity_label(&IssueSeverity::Critical),
                            String::from("B03"),
                        )
                    } else if row.days_until_expiry <= 30 {
                        (
                            self.severity_label(&IssueSeverity::Warning),
                            String::from("B02"),
                        )
                    } else {
                        (
                            self.severity_label(&IssueSeverity::Info),
                            String::from("B02"),
                        )
                    };
                    let secret_cell = format!("{}/{}", row.secret_namespace, row.secret_name);
                    content.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        secret_cell,
                        expired,
                        row.expiry_utc,
                        row.days_until_expiry,
                        level,
                        code_link
                    ));
                }
                content.push('\n');
            }
        }

        // Issues: flat table with Level column (Error/Critical/Warning/Pass). Issue Code is link to doc.
        if !inspection.summary.issues.is_empty() {
            let grouped =
                Self::group_issues_by_severity_and_type(&inspection.summary.issues, self.lang);
            let severity_to_level = |s: &IssueSeverity| self.severity_label(s);
            content.push_str(self.tr().issue_table_header);
            content.push_str("|----------|-------|------------|-------------|\n");
            for sev in &[
                IssueSeverity::Critical,
                IssueSeverity::Warning,
                IssueSeverity::Info,
            ] {
                let level = severity_to_level(sev);
                if let Some(groups) = grouped.get(sev) {
                    for (rule_id, title, _rec, resources) in groups {
                        let code_link = code_cell(rule_id.as_deref());
                        if resources.is_empty() {
                            let res_label =
                                inspection_type_to_resource(&inspection.inspection_type);
                            content.push_str(&format!(
                                "| {} | {} | {} | {} |\n",
                                res_label, level, code_link, title
                            ));
                        } else {
                            for r in resources {
                                content.push_str(&format!(
                                    "| `{}` | {} | {} | {} |\n",
                                    r, level, code_link, title
                                ));
                            }
                        }
                    }
                }
            }
            content.push('\n');
        }

        content.push_str("---\n\n");

        Ok(content)
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{build_disk_rows, mount_depth, normalize_device};
    use crate::node_inspection::types::NodeDiskMount;

    fn mount(device: &str, mp: &str, total: f64) -> NodeDiskMount {
        NodeDiskMount {
            device: device.to_string(),
            mount_point: mp.to_string(),
            fstype: "ext4".to_string(),
            total_g: Some(total),
            used_g: Some(total * 0.5),
            used_pct: Some(50.0),
        }
    }

    #[test]
    fn normalize_device_groups_partitions_to_disks() {
        assert_eq!(normalize_device("/dev/sda1"), "/dev/sda");
        assert_eq!(normalize_device("/dev/sda"), "/dev/sda");
        assert_eq!(normalize_device("/dev/vdb2"), "/dev/vdb");
        assert_eq!(normalize_device("/dev/hdc1"), "/dev/hdc");
        assert_eq!(normalize_device("/dev/nvme0n1p1"), "/dev/nvme0n1");
        assert_eq!(normalize_device("/dev/mmcblk0p1"), "/dev/mmcblk0");
        // 虚拟/整盘设备原样保留
        assert_eq!(
            normalize_device("/dev/mapper/ubuntu--vg-ubuntu--lv"),
            "/dev/mapper/ubuntu--vg-ubuntu--lv"
        );
        assert_eq!(normalize_device("/dev/loop0"), "/dev/loop0");
        assert_eq!(normalize_device("tmpfs"), "tmpfs");
    }

    #[test]
    fn mount_depth_orders_shallow_first() {
        assert_eq!(mount_depth("/"), 0);
        assert_eq!(mount_depth("/data"), 1);
        assert_eq!(mount_depth("/var/lib"), 2);
        assert_eq!(mount_depth("/data/disk1"), 2);
    }

    #[test]
    fn disk_rows_group_by_disk_and_keep_all_real_mounts() {
        // 场景一：系统盘 -> /，数据盘1 -> /data，数据盘2 -> /dbdata，移动设备 -> /mount/upan
        let disks = vec![
            mount("/dev/sda2", "/", 100.0),
            mount("/dev/sdb1", "/data", 500.0),
            mount("/dev/sdc1", "/dbdata", 500.0),
            mount("/dev/sdd1", "/mount/upan", 1000.0),
        ];
        let rows = build_disk_rows(&disks);
        let mps: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(mps, vec!["/", "/data", "/dbdata", "/mount/upan"]);
        assert_eq!(rows[0].1, "/dev/sda");
        assert_eq!(rows[1].1, "/dev/sdb");
    }

    #[test]
    fn disk_rows_keep_subdirectory_mounts_on_different_disks() {
        // 场景二：/data/disk1 与 /data/disk2 在不同磁盘上，都应展示，不折叠到 /data
        let disks = vec![
            mount("/dev/sda2", "/", 100.0),
            mount("/dev/sdb1", "/data/disk1", 300.0),
            mount("/dev/sdc1", "/data/disk2", 400.0),
        ];
        let rows = build_disk_rows(&disks);
        let mps: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(mps, vec!["/", "/data/disk1", "/data/disk2"]);
    }

    #[test]
    fn disk_rows_dedupe_same_device_bind_mounts() {
        // 同一设备同一容量：kubelet local-volume 等绑定挂载只保留最浅挂载点
        let disks = vec![
            mount("/dev/sda2", "/", 100.0),
            mount("/dev/sdb1", "/data", 500.0),
            mount(
                "/dev/sdb1",
                "/var/lib/kubelet/pods/x/volumes/kubernetes.io~local-volume/mid-redis-1",
                500.0,
            ),
        ];
        let rows = build_disk_rows(&disks);
        let mps: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(mps, vec!["/", "/data"]);
    }

    #[test]
    fn disk_rows_exclude_tmpfs_and_loop() {
        let disks = vec![
            mount("/dev/sda2", "/", 100.0),
            mount("tmpfs", "/dev/shm", 4.0),
            mount("/dev/loop0", "/snap/core", 1.0),
        ];
        let rows = build_disk_rows(&disks);
        let mps: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(mps, vec!["/"]);
    }
}
