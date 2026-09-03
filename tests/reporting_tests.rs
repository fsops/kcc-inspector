use chrono::Utc;
use kcc::inspections::types::*;
use kcc::reporting::{issue_to_resource_key, Lang, ReportGenerator, REPORT_RESOURCE_ORDER};
use std::collections::HashMap;
use tempfile::tempdir;

fn make_issue(category: &str, rule_id: Option<&str>) -> Issue {
    Issue {
        severity: IssueSeverity::Info,
        category: category.to_string(),
        description: String::new(),
        resource: None,
        recommendation: String::new(),
        rule_id: rule_id.map(String::from),
    }
}

#[test]
fn test_issue_to_resource_key_mapping() {
    assert_eq!(issue_to_resource_key(&make_issue("Pod", None)), "Pod");
    assert_eq!(issue_to_resource_key(&make_issue("Container", None)), "Pod");
    assert_eq!(issue_to_resource_key(&make_issue("Node", None)), "Node");
    assert_eq!(
        issue_to_resource_key(&make_issue("Service", None)),
        "Service"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Certificates", None)),
        "Certificate"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("ControlPlane", None)),
        "Control Plane"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Autoscaling", None)),
        "HPA"
    );
    assert_eq!(issue_to_resource_key(&make_issue("Policy", None)), "Policy");
    assert_eq!(
        issue_to_resource_key(&make_issue("Observability", None)),
        "Observability"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Security", None)),
        "Security"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Resource Management", None)),
        "Resource Management"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Batch", Some("801"))),
        "CronJob"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Batch", Some("803"))),
        "CronJob"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Batch", Some("804"))),
        "Job"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("Batch", Some("805"))),
        "Job"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("PersistentVolume", None)),
        "PersistentVolume"
    );
    assert_eq!(
        issue_to_resource_key(&make_issue("ClusterRole", None)),
        "ClusterRole"
    );
}

#[test]
fn test_report_resource_order_non_empty() {
    assert!(!REPORT_RESOURCE_ORDER.is_empty());
    assert!(REPORT_RESOURCE_ORDER.contains(&"Pod"));
    assert!(REPORT_RESOURCE_ORDER.contains(&"Node"));
    assert!(REPORT_RESOURCE_ORDER.contains(&"Certificate"));
}

#[tokio::test]
async fn test_report_generation() {
    let generator = ReportGenerator::new();

    // Create test data
    let cluster_report = ClusterReport {
        cluster_name: "test-cluster".to_string(),
        report_id: "test-123".to_string(),
        timestamp: Utc::now(),
        overall_score: 85.5,
        inspections: vec![InspectionResult {
            inspection_type: "Node Health".to_string(),
            timestamp: Utc::now(),
            overall_score: 90.0,
            checks: vec![CheckResult {
                name: "Node Readiness".to_string(),
                description: "Test check".to_string(),
                status: CheckStatus::Pass,
                score: 100.0,
                max_score: 100.0,
                details: Some("All nodes ready".to_string()),
                recommendations: vec![],
            }],
            summary: InspectionSummary {
                total_checks: 1,
                passed_checks: 1,
                warning_checks: 0,
                critical_checks: 0,
                error_checks: 0,
                issues: vec![],
            },
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        }],
        executive_summary: ExecutiveSummary {
            health_status: HealthStatus::Good,
            key_findings: vec!["Test finding".to_string()],
            priority_recommendations: vec!["Test recommendation".to_string()],
            score_breakdown: {
                let mut map = HashMap::new();
                map.insert("Node Health".to_string(), 90.0);
                map
            },
        },
        cluster_overview: Some(ClusterOverview {
            node_count: 1,
            ready_node_count: 1,
            ..Default::default()
        }),
        node_inspection_results: None,
        display_timestamp: None,
        display_timestamp_filename: None,
        recent_events: None,
        db_middleware: None,
    };

    // Test report generation
    let temp_dir = tempdir().unwrap();
    let report_path = temp_dir.path().join("test-report.md");
    let report_path_str = report_path.to_str().unwrap();

    let result = generator
        .generate_report(&cluster_report, report_path_str)
        .await;
    assert!(result.is_ok());

    // Check that files were created
    assert!(report_path.exists());

    let summary_path = temp_dir.path().join("test-report-summary.md");
    assert!(summary_path.exists());

    // Check content (default language is Chinese): Cluster Overview includes Overall Health and score; Executive Summary section removed
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("集群概览"));
    assert!(content.contains("总体健康状态"));
    assert!(content.contains("Kubernetes 集群巡检报告"));
    assert!(content.contains("test-cluster"));
    assert!(content.contains("85.5"));
    // Header "生成时间" falls back to China Standard Time (CST, UTC+8).
    assert!(content.contains("生成时间"));
    assert!(content.contains("CST"));
    assert!(!content.contains("Executive Summary"));

    // The summary report should also be in Chinese by default.
    let summary_content = std::fs::read_to_string(&summary_path).unwrap();
    assert!(summary_content.contains("异常摘要"));
}

#[test]
fn test_report_generation_english() {
    let generator = ReportGenerator::with_lang(Lang::En);

    // Minimal report with one passing check and one issue.
    let cluster_report = ClusterReport {
        cluster_name: "test-cluster".to_string(),
        report_id: "test-123".to_string(),
        timestamp: Utc::now(),
        overall_score: 85.5,
        inspections: vec![InspectionResult {
            inspection_type: "Node Health".to_string(),
            timestamp: Utc::now(),
            overall_score: 90.0,
            checks: vec![CheckResult {
                name: "Node Readiness".to_string(),
                description: "Test check".to_string(),
                status: CheckStatus::Warning,
                score: 80.0,
                max_score: 100.0,
                details: Some("Some nodes not ready".to_string()),
                recommendations: vec![],
            }],
            summary: InspectionSummary {
                total_checks: 1,
                passed_checks: 0,
                warning_checks: 1,
                critical_checks: 0,
                error_checks: 0,
                issues: vec![Issue {
                    severity: IssueSeverity::Warning,
                    category: "Node".to_string(),
                    description: "test issue".to_string(),
                    resource: Some("node-1".to_string()),
                    recommendation: "restart".to_string(),
                    rule_id: Some("001".to_string()),
                }],
            },
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        }],
        executive_summary: ExecutiveSummary {
            health_status: HealthStatus::Good,
            key_findings: vec![],
            priority_recommendations: vec![],
            score_breakdown: HashMap::new(),
        },
        cluster_overview: Some(ClusterOverview {
            node_count: 1,
            ready_node_count: 1,
            ..Default::default()
        }),
        node_inspection_results: None,
        display_timestamp: None,
        display_timestamp_filename: None,
        recent_events: None,
        db_middleware: None,
    };

    let md = generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    assert!(md.contains("Cluster Overview"));
    assert!(md.contains("Overall Health"));
    assert!(md.contains("Kubernetes Cluster Check Report"));
    // English mode must not leak Chinese strings.
    assert!(!md.contains("集群概览"));
    // Issue short title stays English in English mode.
    assert!(md.contains("Node not ready"));
}

#[test]
fn test_report_generation_chinese_issue_titles() {
    let generator = ReportGenerator::with_lang(Lang::Zh);

    let cluster_report = ClusterReport {
        cluster_name: "test-cluster".to_string(),
        report_id: "test-123".to_string(),
        timestamp: Utc::now(),
        overall_score: 70.0,
        inspections: vec![InspectionResult {
            inspection_type: "Node Health".to_string(),
            timestamp: Utc::now(),
            overall_score: 70.0,
            checks: vec![],
            summary: InspectionSummary {
                total_checks: 0,
                passed_checks: 0,
                warning_checks: 0,
                critical_checks: 0,
                error_checks: 0,
                issues: vec![Issue {
                    severity: IssueSeverity::Critical,
                    category: "Node".to_string(),
                    description: "test issue".to_string(),
                    resource: Some("node-1".to_string()),
                    recommendation: "restart".to_string(),
                    rule_id: Some("001".to_string()),
                }],
            },
            certificate_expiries: None,
            pod_container_states: None,
            namespace_summary_rows: None,
        }],
        executive_summary: ExecutiveSummary {
            health_status: HealthStatus::Fair,
            key_findings: vec![],
            priority_recommendations: vec![],
            score_breakdown: HashMap::new(),
        },
        cluster_overview: None,
        node_inspection_results: None,
        display_timestamp: None,
        display_timestamp_filename: None,
        recent_events: None,
        db_middleware: None,
    };

    let md = generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    assert!(md.contains("详细结果"));
    assert!(md.contains("严重"));
    assert!(md.contains("节点未就绪"));
    // 问题代码展示为纯编号（无类别前缀）：`` `001` ``
    assert!(md.contains("`001`"));
}

#[test]
fn test_report_chinese_condition_values() {
    let generator = ReportGenerator::with_lang(Lang::Zh);
    let cluster_report = ClusterReport {
        cluster_name: "c".to_string(),
        report_id: "r".to_string(),
        timestamp: Utc::now(),
        overall_score: 90.0,
        inspections: vec![],
        executive_summary: ExecutiveSummary {
            health_status: HealthStatus::Good,
            key_findings: vec![],
            priority_recommendations: vec![],
            score_breakdown: HashMap::new(),
        },
        cluster_overview: Some(ClusterOverview {
            node_count: 1,
            ready_node_count: 1,
            node_conditions: Some(vec![NodeConditionsRow {
                node_name: "node-1".to_string(),
                ready: "True".to_string(),
                memory_pressure: "False".to_string(),
                disk_pressure: "False".to_string(),
                pid_pressure: "Unknown".to_string(),
            }]),
            ..Default::default()
        }),
        node_inspection_results: None,
        display_timestamp: None,
        display_timestamp_filename: None,
        recent_events: None,
        db_middleware: None,
    };

    let md = generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    // Node condition values are localized: True/False/Unknown -> 是/否/未知.
    assert!(md.contains("| node-1 | 是 | 否 | 否 | 未知 |"));
}

#[test]
fn test_lang_default_is_chinese() {
    assert_eq!(Lang::default(), Lang::Zh);
    let generator = ReportGenerator::new();
    assert_eq!(generator.lang(), Lang::Zh);
}

#[test]
fn test_lang_t_data_layer_selection() {
    // `Lang::t` selects the data-layer variant (used by inspection modules).
    assert_eq!(Lang::Zh.t("Nodes ready", "节点就绪"), "节点就绪");
    assert_eq!(Lang::En.t("Nodes ready", "节点就绪"), "Nodes ready");
    // Localized formatting (`lang_fmt!`) keeps the placeholder structure intact.
    assert_eq!(
        kcc::lang_fmt!(Lang::Zh, "{}/{} ready", "{}/{} 就绪", 2, 3),
        "2/3 就绪"
    );
    assert_eq!(
        kcc::lang_fmt!(Lang::En, "{}/{} ready", "{}/{} 就绪", 2, 3),
        "2/3 ready"
    );
    // The Chinese variant of a data-layer description produced for a zh report.
    let zh_desc = kcc::lang_fmt!(Lang::Zh, "Node {} is not ready", "节点 {} 未就绪", "node-1");
    assert_eq!(zh_desc, "节点 node-1 未就绪");
    // English variant stays English.
    let en_desc = kcc::lang_fmt!(Lang::En, "Node {} is not ready", "节点 {} 未就绪", "node-1");
    assert_eq!(en_desc, "Node node-1 is not ready");
}

#[test]
fn test_report_cluster_kubernetes_displayed_as_default() {
    let generator = ReportGenerator::with_lang(Lang::Zh);
    let mut cluster_report = ClusterReport {
        cluster_name: "kubernetes".to_string(),
        report_id: "test-123".to_string(),
        timestamp: Utc::now(),
        overall_score: 85.0,
        inspections: vec![],
        executive_summary: ExecutiveSummary {
            health_status: HealthStatus::Good,
            key_findings: vec![],
            priority_recommendations: vec![],
            score_breakdown: HashMap::new(),
        },
        cluster_overview: None,
        node_inspection_results: None,
        display_timestamp: None,
        display_timestamp_filename: None,
        recent_events: None,
        db_middleware: None,
    };

    // The generic kubeadm/minikube cluster name "kubernetes" is displayed as
    // "default" in the title and the Cluster line.
    let md = generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    // 中文报告：集群行使用中文标签 **集群**
    assert!(md.contains("# 《default》 Kubernetes 集群巡检报告"));
    assert!(md.contains("**集群**：default"));
    assert!(!md.contains("《kubernetes》"));

    // English mode applies the same normalization.
    let en_generator = ReportGenerator::with_lang(Lang::En);
    let md_en = en_generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    assert!(md_en.contains("# 《default》 Kubernetes Cluster Check Report"));
    assert!(md_en.contains("**Cluster**: default"));

    // Case-insensitive: "Kubernetes" is treated the same way.
    cluster_report.cluster_name = "Kubernetes".to_string();
    let md_ci = generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    assert!(md_ci.contains("# 《default》 Kubernetes 集群巡检报告"));

    // A differently named cluster keeps its real name.
    cluster_report.cluster_name = "prod-cluster".to_string();
    let md_other = generator
        .generate_markdown_string(&cluster_report, None, None, None, None)
        .unwrap();
    assert!(md_other.contains("# 《prod-cluster》 Kubernetes 集群巡检报告"));
    assert!(md_other.contains("**集群**：prod-cluster"));
}

#[test]
fn test_report_formatting() {
    let _generator = ReportGenerator::new();

    // Test that the generator can be created
    assert!(true); // Basic test for now

    // Test scoring integration
    let scoring_engine = kcc::scoring::scoring_engine::ScoringEngine::new();
    let health_status = scoring_engine.get_health_status(85.0);
    assert!(matches!(health_status, HealthStatus::Good));
}
