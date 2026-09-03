//! Report internationalization (i18n): English (`en`) and Chinese (`zh`, default).
//!
//! All report display strings live here as per-language [`Strings`] instances so the
//! report generator never hard-codes a language. The inspection modules also consult
//! [`Lang::t`] to localize data-layer text (check `description` / `recommendation` /
//! `details` and issue `description` / `recommendation`), so the JSON report reflects
//! the selected language as well.

use std::borrow::Cow;

use crate::utils::status::{CheckStatus, HealthStatus, IssueSeverity};

/// Report language. Chinese is the default; `--lang en` switches to English.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Default)]
#[value(rename_all = "kebab-case")]
pub enum Lang {
    /// Chinese (default)
    #[default]
    Zh,
    /// English
    En,
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Lang::Zh => write!(f, "zh"),
            Lang::En => write!(f, "en"),
        }
    }
}

impl Lang {
    /// `lang` attribute for the HTML document.
    pub fn html_lang(&self) -> &'static str {
        match self {
            Lang::Zh => "zh-CN",
            Lang::En => "en",
        }
    }

    /// HTML `<title>` text.
    pub fn html_title(&self) -> &'static str {
        match self {
            Lang::Zh => "kubernetes 巡检报告",
            Lang::En => "kubernetes Report",
        }
    }

    /// Issue severity label.
    pub fn severity_label(&self, severity: &IssueSeverity) -> &'static str {
        match self {
            Lang::En => match severity {
                IssueSeverity::Critical => "Critical",
                IssueSeverity::Warning => "Warning",
                IssueSeverity::Info => "Info",
            },
            Lang::Zh => match severity {
                IssueSeverity::Critical => "严重",
                IssueSeverity::Warning => "警告",
                IssueSeverity::Info => "信息",
            },
        }
    }

    /// Health status label (used in Cluster Overview "Overall Health" row).
    pub fn health_label(&self, status: &HealthStatus) -> &'static str {
        match self {
            Lang::En => match status {
                HealthStatus::Excellent => "Excellent",
                HealthStatus::Good => "Good",
                HealthStatus::Fair => "Fair",
                HealthStatus::Poor => "Poor",
                HealthStatus::Critical => "Critical",
            },
            Lang::Zh => match status {
                HealthStatus::Excellent => "优秀",
                HealthStatus::Good => "良好",
                HealthStatus::Fair => "一般",
                HealthStatus::Poor => "较差",
                HealthStatus::Critical => "严重",
            },
        }
    }

    /// Check status cell text (emoji + label).
    pub fn check_status_text(&self, status: &CheckStatus) -> &'static str {
        match self {
            Lang::En => match status {
                CheckStatus::Pass => "✅ Pass",
                CheckStatus::Warning => "⚠️ Warning",
                CheckStatus::Critical => "❌ Critical",
                CheckStatus::Error => "💥 Error",
            },
            Lang::Zh => match status {
                CheckStatus::Pass => "✅ 通过",
                CheckStatus::Warning => "⚠️ 警告",
                CheckStatus::Critical => "❌ 严重",
                CheckStatus::Error => "💥 错误",
            },
        }
    }

    /// Localized container-usage "Note" cell for a `notable_reason` value.
    pub fn container_note<'a>(&self, reason: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(reason);
        }
        match reason {
            "high_usage" => Cow::Borrowed("高使用率"),
            "low_usage" => Cow::Borrowed("低使用率"),
            "no_request_no_limit" => Cow::Borrowed("无请求"),
            _ => Cow::Borrowed(reason),
        }
    }

    /// Localized boolean/condition cell value for the node conditions table
    /// ("True" / "False" / "Unknown" -> 是 / 否 / 未知).
    pub fn condition_value<'a>(&self, v: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(v);
        }
        match v {
            "True" => Cow::Borrowed("是"),
            "False" => Cow::Borrowed("否"),
            "Unknown" => Cow::Borrowed("未知"),
            _ => Cow::Borrowed(v),
        }
    }

    /// Localized SELinux mode ("Enforcing" / "Permissive" / "Disabled").
    pub fn selinux_mode<'a>(&self, v: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(v);
        }
        match v {
            "Enforcing" => Cow::Borrowed("强制模式"),
            "Permissive" => Cow::Borrowed("宽容模式"),
            "Disabled" => Cow::Borrowed("已禁用"),
            _ => Cow::Borrowed(v),
        }
    }

    /// Localized node condition type ("Ready" / "MemoryPressure" / "DiskPressure" /
    /// "PIDPressure"), used inside data-layer issue descriptions.
    pub fn condition_type_name<'a>(&self, t: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(t);
        }
        match t {
            "Ready" => Cow::Borrowed("就绪"),
            "MemoryPressure" => Cow::Borrowed("内存压力"),
            "DiskPressure" => Cow::Borrowed("磁盘压力"),
            "PIDPressure" => Cow::Borrowed("PID 压力"),
            _ => Cow::Borrowed(t),
        }
    }

    /// Pick the English or Chinese variant of a data-layer string. Used by the
    /// inspection modules for localized `description` / `recommendation` / `details`
    /// text; the two variants must contain the same `format!` placeholders (checked
    /// in debug builds, see [`count_format_placeholders`]).
    pub fn t<'a>(&self, en: &'a str, zh: &'a str) -> &'a str {
        debug_assert_eq!(
            count_format_placeholders(en),
            count_format_placeholders(zh),
            "Lang::t: en/zh variants must contain the same number of format! placeholders; en={} zh={}",
            en,
            zh
        );
        match self {
            Lang::En => en,
            Lang::Zh => zh,
        }
    }

    /// Localized check name (Check Results "Check Item" column). Falls back to the
    /// original name for unknown entries so the report still works with future checks.
    pub fn check_name<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(name);
        }
        match name {
            // Node
            "Node Readiness" => Cow::Borrowed("节点就绪"),
            "Node Pressure" => Cow::Borrowed("节点压力"),
            "Node process health" => Cow::Borrowed("节点进程健康"),
            // Pod
            "Pod Health" => Cow::Borrowed("Pod 健康"),
            "Pod Stability" => Cow::Borrowed("Pod 稳定性"),
            // Resource
            "Resource Requests" => Cow::Borrowed("资源请求"),
            "Resource Limits" => Cow::Borrowed("资源限制"),
            "Complete Resource Configuration" => Cow::Borrowed("完整资源配置"),
            // Network
            "DNS Configuration" => Cow::Borrowed("DNS 配置"),
            "Service Configuration" => Cow::Borrowed("服务配置"),
            "Network Policy Coverage" => Cow::Borrowed("网络策略覆盖率"),
            // Storage
            "Persistent Volume Health" => Cow::Borrowed("持久卷健康"),
            "PVC Binding" => Cow::Borrowed("PVC 绑定"),
            "Storage Class Configuration" => Cow::Borrowed("存储类配置"),
            // Security
            "RBAC Configuration" => Cow::Borrowed("RBAC 配置"),
            "Pod Security Standards" => Cow::Borrowed("Pod 安全标准"),
            "Service Account Usage" => Cow::Borrowed("服务账号使用"),
            // Control plane
            "Component Status" => Cow::Borrowed("组件状态"),
            "Control Plane Pods" => Cow::Borrowed("控制平面 Pod"),
            // Autoscaling
            "Horizontal Pod Autoscalers" => Cow::Borrowed("水平 Pod 自动伸缩"),
            // Batch
            "CronJobs" => Cow::Borrowed("CronJobs"),
            "Jobs" => Cow::Borrowed("Jobs"),
            // Policy & governance
            "Resource Quotas" => Cow::Borrowed("资源配额"),
            "Limit Ranges" => Cow::Borrowed("LimitRange"),
            "Pod Disruption Budgets" => Cow::Borrowed("Pod 中断预算 (PDB)"),
            // Observability
            "Metrics Pipeline" => Cow::Borrowed("指标管道"),
            "Cluster DNS (CoreDNS)" => Cow::Borrowed("集群 DNS (CoreDNS)"),
            "Logging Stack" => Cow::Borrowed("日志栈"),
            "Monitoring & Alerting" => Cow::Borrowed("监控与告警"),
            // Certificates
            "TLS certificate expiry" => Cow::Borrowed("TLS 证书过期"),
            "CertificateSigningRequests" => Cow::Borrowed("证书签名请求 (CSR)"),
            // Namespace
            "Namespace summary" => Cow::Borrowed("命名空间摘要"),
            _ => Cow::Borrowed(name),
        }
    }

    /// Localized inspection module type name (module-level statistics only; the
    /// machine-readable `inspection_type` stays English in JSON data).
    pub fn inspection_type_name<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(name);
        }
        match name {
            "Node Health" => Cow::Borrowed("节点健康"),
            "Node Inspection" => Cow::Borrowed("节点巡检"),
            "Pod Status" => Cow::Borrowed("Pod 状态"),
            "Security Configuration" => Cow::Borrowed("安全配置"),
            "Resource Usage" => Cow::Borrowed("资源使用"),
            "Network Connectivity" => Cow::Borrowed("网络连通性"),
            "Storage" => Cow::Borrowed("存储"),
            "Control Plane" => Cow::Borrowed("控制平面"),
            "Autoscaling" => Cow::Borrowed("自动伸缩"),
            "Batch Workloads" => Cow::Borrowed("批处理工作负载"),
            "Policy & Governance" => Cow::Borrowed("策略与治理"),
            "Observability" => Cow::Borrowed("可观测性"),
            "Upgrade Readiness" => Cow::Borrowed("升级就绪"),
            "Namespace" => Cow::Borrowed("命名空间"),
            "Certificates" => Cow::Borrowed("证书"),
            _ => Cow::Borrowed(name),
        }
    }

    /// Localized issue category name (summary report). Falls back to the original.
    pub fn category_name<'a>(&self, category: &'a str) -> Cow<'a, str> {
        if matches!(self, Lang::En) {
            return Cow::Borrowed(category);
        }
        match category {
            "Container" => Cow::Borrowed("容器"),
            "Pod" => Cow::Borrowed("Pod"),
            "Node" => Cow::Borrowed("节点"),
            "Service" => Cow::Borrowed("服务"),
            "Deployment" => Cow::Borrowed("Deployment"),
            "Namespace" => Cow::Borrowed("命名空间"),
            "PersistentVolume" => Cow::Borrowed("持久卷 (PV)"),
            "PersistentVolumeClaim" => Cow::Borrowed("持久卷声明 (PVC)"),
            "StorageClass" => Cow::Borrowed("存储类"),
            "ClusterRole" => Cow::Borrowed("集群角色"),
            "ClusterRoleBinding" => Cow::Borrowed("集群角色绑定"),
            "ServiceAccount" => Cow::Borrowed("服务账号"),
            "NetworkPolicy" => Cow::Borrowed("网络策略"),
            "Security" => Cow::Borrowed("安全"),
            "Policy" => Cow::Borrowed("策略"),
            "Batch" => Cow::Borrowed("批处理"),
            "Autoscaling" => Cow::Borrowed("自动伸缩"),
            "Certificates" => Cow::Borrowed("证书"),
            "ControlPlane" => Cow::Borrowed("控制平面"),
            "Observability" => Cow::Borrowed("可观测性"),
            "Resource Management" => Cow::Borrowed("资源管理"),
            _ => Cow::Borrowed(category),
        }
    }
}

/// Localized formatting for the inspection modules: applies `format!` to the
/// English or Chinese variant of a message template, chosen by the language.
/// Both variants must be string literals with matching placeholder structure;
/// each variant is compile-time checked against the supplied arguments, so a
/// template/argument mismatch fails the build instead of panicking at runtime.
///
/// `format!` rejects runtime (non-literal) format strings, so this macro is the
/// stable replacement for `format!(self.lang.t(en, zh), args...)`.
#[macro_export]
macro_rules! lang_fmt {
    ($lang:expr, $en:literal, $zh:literal $(, $arg:expr)*) => {
        match $lang {
            $crate::utils::lang::Lang::En => format!($en $(, $arg)*),
            $crate::utils::lang::Lang::Zh => format!($zh $(, $arg)*),
        }
    };
}

/// Localized formatting for the report generator: formats the [`Strings`] field
/// `$field` (a template only known at runtime) with the supplied arguments via
/// [`fmt_dynamic`]. Arguments are borrowed and coerced to `&dyn Display`; for
/// precise numeric output (e.g. `{:.1}`) pre-format the value with a literal
/// `format!` at the call site.
#[macro_export]
macro_rules! tr_fmt {
    ($s:expr, $field:ident $(, $arg:expr)*) => {
        $crate::utils::lang::fmt_dynamic($s.tr().$field, &[ $( &( $arg ) ),* ])
    };
}

/// Substitute `{...}` placeholders in a runtime-selected template with the given
/// arguments. `format!` requires a literal format string, so this helper is used
/// where the localized template (a [`Strings`] field) is only known at runtime.
/// Each `{}` / `{:?}` / `{:.N}` placeholder consumes the next argument (rendered
/// with `Display`); missing arguments leave the placeholder literal, and extra
/// arguments are ignored, so this never panics. Templates must not contain
/// literal `{` / `}` braces (no `{{` / `}}` escape handling) — none of the
/// current [`Strings`] templates do.
pub fn fmt_dynamic(template: &str, args: &[&dyn std::fmt::Display]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    let mut idx = 0usize;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let tail = &rest[open..];
        if let Some(close) = tail.find('}') {
            if let Some(arg) = args.get(idx) {
                let _ = write!(out, "{}", arg);
                idx += 1;
            } else {
                out.push_str(&tail[..=close]);
            }
            rest = &tail[close + 1..];
        } else {
            out.push_str(tail);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

/// Count `format!` placeholders in a template: every unescaped `{` starts one
/// (`{}`, `{:?}`, `{0}` …); `{{` / `}}` are escaped literal braces.
fn count_format_placeholders(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    i += 2; // escaped literal `{`
                } else {
                    count += 1;
                    i += 1;
                }
            }
            b'}' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                    i += 2; // escaped literal `}`
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    count
}

#[cfg(test)]
mod placeholder_tests {
    use super::*;

    #[test]
    fn count_placeholders_matches_expected() {
        assert_eq!(count_format_placeholders("Node {} is not ready"), 1);
        assert_eq!(count_format_placeholders("{}/{} nodes are ready"), 2);
        assert_eq!(
            count_format_placeholders("Detected kubelet versions: {:?}"),
            1
        );
        assert_eq!(count_format_placeholders("no placeholders here"), 0);
        assert_eq!(count_format_placeholders("escaped {{ braces }}"), 0);
    }

    #[test]
    fn t_asserts_placeholder_parity() {
        // A pair with mismatched placeholders must trip the debug_assert in `t`.
        // The check is a `debug_assert_eq!`, which is a no-op under `--release`;
        // only verify it triggers parity panics in debug builds.
        if cfg!(debug_assertions) {
            let result = std::panic::catch_unwind(|| {
                Lang::Zh.t("{}/{} ready", "就绪");
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn lang_fmt_selects_language() {
        assert_eq!(
            crate::lang_fmt!(Lang::Zh, "{} ready", "{} 就绪", 2),
            "2 就绪"
        );
        assert_eq!(
            crate::lang_fmt!(Lang::En, "{} ready", "{} 就绪", 2),
            "2 ready"
        );
    }

    #[test]
    fn fmt_dynamic_substitutes_placeholders() {
        assert_eq!(fmt_dynamic("x {} y", &[&1u32]), "x 1 y");
        assert_eq!(fmt_dynamic("a {} b {} c", &[&"A", &2u32]), "a A b 2 c");
        assert_eq!(fmt_dynamic("no placeholders", &[&1u32]), "no placeholders");
        assert_eq!(fmt_dynamic("missing {} arg", &[]), "missing {} arg");
        assert_eq!(fmt_dynamic("extra {}", &[&1u32, &2u32]), "extra 1");
        // `{:.N}` consumes one arg (pre-formatted at the call site).
        assert_eq!(fmt_dynamic("{:.1}", &[&"87.5"]), "87.5");
    }
}

/// Defines the per-language [`Strings`] struct plus the `EN` / `ZH` instances and the
/// language lookup. Each field is a full Markdown fragment (may contain `{}`
/// placeholders and trailing newlines) in English and Chinese.
macro_rules! strings {
    ($( $field:ident : $en:expr, $zh:expr ),* $(,)?) => {
        /// All report display strings for one language (full Markdown fragments,
        /// usable directly or as a `format!` template).
        #[derive(Debug, Clone, Copy)]
        pub struct Strings {
            $( pub $field: &'static str ),*
        }

        /// English strings.
        pub const EN: Strings = Strings { $( $field: $en ),* };

        /// Chinese strings (default).
        pub const ZH: Strings = Strings { $( $field: $zh ),* };

        impl Strings {
            /// Returns the strings for a language.
            pub fn get(lang: Lang) -> &'static Strings {
                match lang {
                    Lang::Zh => &ZH,
                    Lang::En => &EN,
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            /// Every EN/ZH template pair must contain the same number of `{}`
            /// placeholders, and each template must render cleanly via
            /// `fmt_dynamic` with exactly that many arguments (the report
            /// generator formats these at runtime, so argument counts cannot be
            /// checked at compile time).
            #[test]
            fn en_zh_templates_placeholder_parity() {
                $(
                    let en = count_format_placeholders($en);
                    let zh = count_format_placeholders($zh);
                    assert_eq!(
                        en,
                        zh,
                        "placeholder count mismatch for `{}`: en={} zh={}",
                        stringify!($field),
                        en,
                        zh
                    );
                    // Render both variants with exactly `en` dummy args; every
                    // placeholder must be consumed (no literal braces remain).
                    let dummy: Vec<String> = (0..en).map(|i| format!("arg{}", i)).collect();
                    let refs: Vec<&dyn std::fmt::Display> =
                        dummy.iter().map(|s| s as &dyn std::fmt::Display).collect();
                    let out_en = fmt_dynamic($en, &refs);
                    let out_zh = fmt_dynamic($zh, &refs);
                    assert!(
                        !out_en.contains('{') && !out_en.contains('}'),
                        "unconsumed placeholder in `{}` (en)",
                        stringify!($field)
                    );
                    assert!(
                        !out_zh.contains('{') && !out_zh.contains('}'),
                        "unconsumed placeholder in `{}` (zh)",
                        stringify!($field)
                    );
                )*
            }
        }
    };
}

strings! {
    // ---- Report header ----
    title_fmt:
        "# 《{}》 Kubernetes Cluster Check Report\n\n",
        "# 《{}》 Kubernetes 集群巡检报告\n\n",
    report_id_label:
        "**Report ID**: `{}`\n\n",
        "**报告 ID**：`{}`\n\n",
    cluster_label:
        "**Cluster**: {}\n\n",
        "**集群**：{}\n\n",
    generated_at_label:
        "**Generated At**: {}\n\n",
        "**生成时间**：{}\n\n",

    // ---- Cluster overview ----
    cluster_overview_title:
        "## 🖥️ Cluster Overview\n\n",
        "## 🖥️ 集群概览\n\n",
    metric_value_header:
        "| Metric | Value |\n",
        "| 指标 | 值 |\n",
    overview_unavailable:
        "Cluster overview is not available (ensure cluster is reachable and the tool has been rebuilt).\n\n",
        "集群概览不可用（请确保集群可达且工具已重新构建）。\n\n",
    cluster_version_label: "| Cluster Version | {} |\n", "| 集群版本 | {} |\n",
    node_count_label: "| Node Count | {} |\n", "| 节点数 | {} |\n",
    ready_nodes_label: "| Ready Nodes | {} |\n", "| 就绪节点数 | {} |\n",
    pod_count_label: "| Pod Count | {} |\n", "| Pod 数 | {} |\n",
    namespace_count_label: "| Namespace Count | {} |\n", "| 命名空间数 | {} |\n",
    cluster_age_label: "| Cluster Age (days) | {} |\n", "| 集群年龄（天） | {} |\n",
    container_runtime_label: "| Container Runtime | {} |\n", "| 容器运行时 | {} |\n",
    overall_health_fmt:
        "| Overall Health | {} {} (Score: {:.1}) |\n",
        "| 总体健康状态 | {} {}（得分：{:.1}） |\n",

    // ---- Node conditions ----
    node_conditions_title: "### Node conditions\n\n", "### 节点状态\n\n",
    node_conditions_header:
        "| Node | Ready | MemoryPressure | DiskPressure | PIDPressure |\n",
        "| 节点 | 就绪 | 内存压力 | 磁盘压力 | PID 压力 |\n",

    // ---- Workload summary ----
    workload_title: "### Workload summary\n\n", "### 工作负载摘要\n\n",
    workload_header: "| Controller | Total | Ready |\n", "| 控制器 | 总数 | 就绪 |\n",

    // ---- Storage summary ----
    storage_title: "### Storage summary\n\n", "### 存储摘要\n\n",
    pv_total_label: "| PV total | {} |\n", "| PV 总数 | {} |\n",
    pvc_total_label: "| PVC total | {} |\n", "| PVC 总数 | {} |\n",
    pvc_bound_label: "| PVC Bound | {} |\n", "| PVC 已绑定 | {} |\n",
    storage_class_count_label: "| StorageClass count | {} |\n", "| StorageClass 数量 | {} |\n",
    default_storage_class_label: "| Default StorageClass | {} |\n\n", "| 默认 StorageClass | {} |\n\n",

    // ---- Container resource usage ----
    container_usage_title:
        "### Container resource usage (top 20 high usage)\n\n",
        "### 容器资源使用（按使用率排名前 20）\n\n",
    container_usage_desc:
        "Top 20 containers by usage vs limit (CPU or memory ≥ 80% of limit). Data from **metrics-server** (Pod metrics API) and **Pod spec** (limits). This section is **omitted when metrics-server is unavailable**.\n\n",
        "按使用率排名前 20 的容器（使用量 vs 限制，CPU 或内存 ≥ 限制的 80%）。数据来自 **metrics-server**（Pod 指标 API）和 **Pod spec**（限制）。当 **metrics-server 不可用**时，此部分将被**省略**。\n\n",
    container_usage_header:
        "| Namespace | Pod | Container | CPU used (m) | CPU request (m) | CPU limit (m) | Mem used (Mi) | Mem request (Mi) | Mem limit (Mi) | Note |\n",
        "| 命名空间 | Pod | 容器 | CPU 使用 (m) | CPU 请求 (m) | CPU 限制 (m) | 内存使用 (Mi) | 内存请求 (Mi) | 内存限制 (Mi) | 备注 |\n",

    // ---- Node inspection ----
    node_inspection_title: "## 🔍 Node Inspection\n\n", "## 🔍 节点巡检\n\n",
    node_inspection_desc:
        "Per-node checks from kcc-inspector DaemonSet.\n\n",
        "来自 kcc-inspector DaemonSet 的每个节点检查。\n\n",
    node_inspection_no_data:
        "No data (kcc-inspector DaemonSet not deployed or collection failed / no pods ready).\n\n",
        "无数据（kcc-inspector DaemonSet 未部署，或采集失败 / 无就绪 Pod）。\n\n",
    node_general_info_title: "### Node General Information\n\n", "### 节点基本信息\n\n",
    node_general_info_header:
        "| Node | OS Version | IP Address | Kernel Version | Uptime | Collection time |\n",
        "| 节点 | 操作系统版本 | IP 地址 | 内核版本 | 运行时间 | 采集时间 |\n",
    node_resources_title: "### Node resources\n\n", "### 节点资源\n\n",
    node_resources_header:
        "| Node | CPU (cores) | CPU Used | CPU % | Mem Total (Gi) | Mem Used (Gi) | Mem % | Swap Total (Gi) | Swap Used (Gi) | Swap % | Load (1m, 5m, 15m) |\n",
        "| 节点 | CPU (核心) | CPU 已用 | CPU 百分比 | 内存总量 (Gi) | 内存已用 (Gi) | 内存百分比 | Swap 总量 (Gi) | Swap 已用 (Gi) | Swap 百分比 | 负载 (1m, 5m, 15m) |\n",
    node_disk_usage_title: "### Node disk usage\n\n", "### 节点磁盘使用\n\n",
    node_disk_usage_desc: "", "",
    node_disk_usage_header:
        "| Node | Mount Point | Device | FSType | Total (Gi) | Used (Gi) | Used % | Status |\n",
        "| 节点 | 挂载点 | 设备 | 文件系统类型 | 总量 (Gi) | 已用 (Gi) | 已用百分比 | 状态 |\n",
    node_container_state_title: "### Node container state counts\n\n", "### 节点容器状态统计\n\n",
    node_container_state_header:
        "| Node | Running | Waiting | Exited |\n",
        "| 节点 | 运行中 | 等待中 | 已退出 |\n",
    node_service_status_title:
        "## ⚙️ Node component and service status\n\n",
        "## ⚙️ 节点组件与服务状态\n\n",
    node_service_status_header:
        "| Node/Service | Kubelet | Container runtime | NTP synced | Journald | Crontab |\n",
        "| 节点/服务 | Kubelet | 容器运行时 | NTP 同步 | Journald | Crontab |\n",
    service_enabled: "enabled", "已启用",
    service_disabled: "disabled", "已禁用",
    service_none: "None", "无",
    node_security_title:
        "### Node security and kernel modules\n\n",
        "### 节点安全与内核模块\n\n",
    node_security_desc:
        "SELinux, firewalld, IPVS, br_netfilter, overlay, and nf_conntrack status; helps troubleshoot network and security policy.\n\n",
        "SELinux、firewalld、IPVS、br_netfilter、overlay 和 nf_conntrack 状态；用于排查网络和安全策略问题。\n\n",
    node_security_header:
        "| Node | SELinux | Firewalld | IPVS | br_netfilter | overlay | nf_conntrack |\n",
        "| 节点 | SELinux | Firewalld | IPVS | br_netfilter | overlay | nf_conntrack |\n",
    yes_label: "Yes", "是",
    no_label: "No", "否",
    firewalld_active: "Active", "已激活",
    firewalld_inactive: "Inactive", "未激活",
    node_network_title: "### Node network and stability\n\n", "### 节点网络与稳定性\n\n",
    node_network_desc:
        "Conntrack usage, inode usage, OOM count, open FDs, and zombie count; used to assess node stability and resource pressure.\n\n",
        "Conntrack 使用率、Inode 使用率、OOM 次数、已打开 FD 数和僵尸进程数；用于评估节点稳定性和资源压力。\n\n",
    node_network_header:
        "| Node | Conntrack usage % | Inode usage % | OOM count | FD (open/max) | Zombie count |\n",
        "| 节点 | Conntrack 使用率 | Inode 使用率 | OOM 次数 | FD (已开/最大) | 僵尸进程数 |\n",
    node_kernel_title: "### Node kernel parameters\n\n", "### 节点内核参数\n\n",
    node_kernel_desc:
        "ip_forward, swappiness, and somaxconn; affects network forwarding, memory swapping, and connection queue.\n\n",
        "ip_forward、swappiness 和 somaxconn；影响网络转发、内存交换和连接队列。\n\n",
    node_kernel_header:
        "| Node | net.ipv4.ip_forward | vm.swappiness | net.core.somaxconn |\n",
        "| 节点 | net.ipv4.ip_forward | vm.swappiness | net.core.somaxconn |\n",
    node_certificate_title: "### Node Certificate Status\n\n", "### 节点证书状态\n\n",
    node_certificate_header:
        "| Node | Path | Expired | Expiration Date (node local) | Days to Expiry | Level | Issue Code |\n",
        "| 节点 | 路径 | 已过期 | 过期时间（节点本地） | 剩余天数 | 级别 | 问题代码 |\n",

    // ---- Recent cluster events ----
    events_title:
        "## 📢 Recent cluster events\n\n",
        "## 📢 近期集群事件\n\n",
    events_header:
        "| Namespace | Object | Level | Reason | Message | Last seen |\n",
        "| 命名空间 | 对象 | 级别 | 原因 | 消息 | 最后出现 |\n",

    // ---- Database middleware ----
    db_middleware_title: "## 🗄️ Database Middleware\n\n", "## 🗄️ 数据库中间件\n\n",
    db_middleware_desc:
        "Database middleware pods detected by container image.\n\n",
        "按容器镜像名检测到的数据库中间件 Pod。\n\n",
    db_middleware_header:
        "| Namespace | Pod | Image | Ready | Restarts |\n",
        "| 命名空间 | Pod | 镜像 | 就绪 | 重启次数 |\n",
    db_middleware_none:
        "No database middleware pods detected.\n\n",
        "未检测到数据库中间件 Pod。\n\n",

    // ---- Detailed results / check results ----
    detailed_results_title: "## 📋 Detailed Results\n\n", "## 📋 详细结果\n\n",
    check_results_title: "### Check Results\n\n", "### 检查结果\n\n",
    check_results_title_4: "#### Check Results\n\n", "#### 检查结果\n\n",
    check_results_header:
        "| Resource | Check Item | Status | Score | Details |\n",
        "| 资源 | 检查项 | 状态 | 得分 | 详情 |\n",
    check_results_header_no_resource:
        "| Check Item | Status | Score | Details |\n",
        "| 检查项 | 状态 | 得分 | 详情 |\n",
    // ---- Namespace summary ----
    namespace_summary_title: "### Namespace summary\n\n", "### 命名空间摘要\n\n",
    namespace_summary_header:
        "| Namespace | Pods | Deployments | NetworkPolicy | ResourceQuota | LimitRange |\n",
        "| 命名空间 | Pod 数 | Deployment 数 | 网络策略 | 资源配额 | LimitRange |\n",

    // ---- Issues / certificates ----
    tls_cert_expiry_title: "#### TLS Certificate Expiry\n\n", "#### TLS 证书过期\n\n",
    tls_cert_header:
        "| Secret (namespace/name) | Expired | Expiry (UTC) | Days to Expiry | Level | Issue Code |\n",
        "| Secret（命名空间/名称） | 已过期 | 过期时间 (UTC) | 剩余天数 | 级别 | 问题代码 |\n",
    issue_table_header:
        "| Resource | Level | Issue Code | Short Title |\n",
        "| 资源 | 级别 | 问题代码 | 简要描述 |\n",
    issue_table_header_no_level:
        "| Resource | Issue Code | Short Title |\n",
        "| 资源 | 问题代码 | 简要描述 |\n",

    // ---- Footer ----
    footer:
        "*Report generated by Limonergy.*\n",
        "*报告由 Limonergy 生成。*\n",

    // ---- Summary (exception) report ----
    summary_title:
        "# Cluster Inspection – Exception Summary\n\n",
        "# 集群巡检 – 异常摘要\n\n",
    issue_statistics_title: "## Issue Statistics\n\n", "## 问题统计\n\n",
    severity_count_ratio_header: "| Severity | Count | Ratio |\n", "| 级别 | 数量 | 占比 |\n",
    critical_issues_title: "## Critical Issues\n\n", "## 严重问题\n\n",
    immediate_action: "> Immediate action required.\n\n", "> 需要立即处理。\n\n",
    other_issues_title: "## Other Issues\n\n", "## 其他问题\n\n",
    other_issues_header:
        "| Code | Severity | Category | Count | Sample Resource | Recommendation |\n",
        "| 代码 | 级别 | 类别 | 数量 | 示例资源 | 建议 |\n",
    recs_by_category_title:
        "## 🎯 Recommendations by Category\n\n",
        "## 🎯 按类别建议\n\n",
    rec_count_fmt: "- {} ({} issues)\n", "- {}（{} 个问题）\n",

    // ---- Module-level statistics (diagnostics) ----
    statistics_title: "### 📈 Cluster Statistics\n\n", "### 📈 集群统计\n\n",
    modules_checked_label: "| Modules Checked | {} |\n", "| 已检查模块数 | {} |\n",
    total_checks_label: "| Total Checks | {} |\n", "| 总检查数 | {} |\n",
    total_issues_label: "| Total Issues | {} |\n", "| 问题总数 | {} |\n",
    distinct_categories_label:
        "| Distinct Resource Categories | {} |\n\n",
        "| 不同资源类别数 | {} |\n\n",
    top_categories_title:
        "**Top Resource Categories by Issue Count (Top 5)**\n\n",
        "**按问题数量排名前 5 的资源类别**\n\n",
    top_cat_item_fmt: "- {}: {} issues\n", "- {}：{} 个问题\n",
    best_module_fmt: "**Best Module**: {} ({:.1} points)\n\n", "**最佳模块**：{}（{:.1} 分）\n\n",
    worst_module_fmt: "**Worst Module**: {} ({:.1} points)\n\n", "**最差模块**：{}（{:.1} 分）\n\n",

    // ---- Per-inspection formatting ----
    inspection_score_title_fmt: "### {} (Score: {:.1}/100)\n\n", "### {}（得分：{:.1}/100）\n\n",
    check_items_fmt:
        "**Check Items**: {} | **Pass**: {} | **Warning**: {} | **Critical**: {} | **Error**: {}\n\n",
        "**检查项**：{} | **通过**：{} | **警告**：{} | **严重**：{} | **错误**：{}\n\n",
}
