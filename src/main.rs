use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use log::info;

mod cli;
mod config;
mod inspections;
mod jobs;
mod k8s;
mod node_inspection;
mod reporting;
mod scoring;
mod server;
mod utils;

use cli::{Args, Commands, InspectionType, ReportFormat};
use config::{Config, NodeAccess, NodeAccessMode};
use inspections::types::ClusterReport;
use inspections::InspectionRunner;
use k8s::client::K8sClient;
use reporting::generator::parse_check_level_filter;
use reporting::ReportGenerator;
use utils::lang::Lang;

fn output_path_with_extension(
    path: Option<String>,
    report: &ClusterReport,
    format: ReportFormat,
) -> String {
    let ext = match format {
        ReportFormat::Md => "md",
        ReportFormat::Json => "json",
        ReportFormat::Csv => "csv",
        ReportFormat::Html => "html",
    };
    let default_name = {
        let ts = report
            .display_timestamp_filename
            .clone()
            .unwrap_or_else(|| report.timestamp.format("%Y-%m-%d-%H%M%S").to_string());
        format!("kubernetes-inspection-report-{}.{}", ts, ext)
    };
    let path = path.unwrap_or(default_name);
    if path.ends_with('.') || !path.contains('.') {
        format!("{}.{}", path.trim_end_matches('.'), ext)
    } else {
        path
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    match args.command {
        Commands::Check {
            cluster_name,
            namespace,
            node_inspector_namespace,
            output,
            format,
            config_file,
            kubeconfig,
            level,
            lang,
            node_access_mode,
            node_inspector_port,
        } => {
            run_check_command(
                cluster_name,
                namespace,
                node_inspector_namespace,
                output,
                format,
                config_file,
                kubeconfig,
                level,
                lang,
                node_access_mode,
                node_inspector_port,
            )
            .await?;
        }
        Commands::Server {
            addr,
            web_base,
            config_file,
            kubeconfig,
            node_access_mode,
            node_inspector_port,
        } => {
            let mut cfg = Config::load(config_file.as_deref())?;
            // 优先级：--kubeconfig 参数 > KCC_KUBECONFIG 环境变量 > kcc.yaml 的 kubeconfig
            cfg.kubeconfig = kubeconfig.or(cfg.kubeconfig);
            cfg.server_addr = addr;
            cfg.web_base = web_base;
            // CLI 参数缺省时不覆盖环境变量/配置文件中的值（否则默认值会遮蔽 KCC_NODE_ACCESS_MODE 等）
            if let Some(mode) = node_access_mode {
                cfg.node_access.mode = parse_access_mode(&mode);
            }
            if let Some(port) = node_inspector_port {
                cfg.node_access.port = port;
            }
            server::serve(cfg).await?;
        }
        Commands::NodeInspector { addr } => {
            let mut cfg = Config::load(None)?;
            cfg.node_inspector_addr = addr;
            server::serve_node(cfg).await?;
        }
    }

    Ok(())
}

fn parse_access_mode(s: &str) -> NodeAccessMode {
    match s.to_lowercase().as_str() {
        "cluster_ip_service" | "service" => NodeAccessMode::ClusterIpService,
        _ => NodeAccessMode::PodIp,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_check_command(
    cluster_name: Option<String>,
    namespace: Option<String>,
    node_inspector_namespace: String,
    output: Option<String>,
    format: ReportFormat,
    config_file: Option<String>,
    kubeconfig: Option<String>,
    level: String,
    lang: Lang,
    node_access_mode: String,
    node_inspector_port: u16,
) -> Result<()> {
    println!("{}", "🔍 Kubernetes 集群巡检".bright_cyan().bold());
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_cyan()
    );

    info!("Starting Kubernetes cluster check");

    // kcc.yaml 配置（若指定）；当前主要读取其中的 kubeconfig，其余项仍以命令行参数为准
    let cfg = Config::load(config_file.as_deref())?;
    // 优先级：--kubeconfig 参数 > KCC_KUBECONFIG 环境变量 > kcc.yaml 的 kubeconfig
    let kubeconfig = kubeconfig.or(cfg.kubeconfig.clone());

    println!("📋 {}", "配置:".bright_yellow().bold());
    println!(
        "   检查范围: {}",
        namespace
            .as_deref()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "所有命名空间".to_string())
            .bright_green()
    );
    println!(
        "   节点客户端 DaemonSet 命名空间: {}",
        node_inspector_namespace.bright_green()
    );
    println!(
        "   节点采集方式: {}",
        parse_access_mode(&node_access_mode)
            .to_string()
            .bright_green()
    );
    println!(
        "   输出文件: {}",
        output.as_deref().unwrap_or("(auto)").bright_green()
    );
    println!(
        "   报告语言类型: {}",
        match lang {
            Lang::Zh => "中文 (zh)",
            Lang::En => "English (en)",
        }
        .bright_green()
    );
    println!();

    print!("🔗 正在连接集群... ");
    let client = match K8sClient::new(kubeconfig.as_deref()).await {
        Ok(client) => {
            println!("{}", "✅ 成功".bright_green());
            client
        }
        Err(e) => {
            println!("{}", "❌ 失败".bright_red());
            eprintln!("错误: {}", e);
            return Err(e);
        }
    };

    println!("🔍 正在执行巡检...");
    let runner = InspectionRunner::new(client).with_lang(lang);
    let access = NodeAccess {
        mode: parse_access_mode(&node_access_mode),
        port: node_inspector_port,
        timeout_secs: 30,
    };

    let results = match runner
        .run_inspections_ex(
            InspectionType::All,
            namespace.as_deref(),
            &node_inspector_namespace,
            &cfg.node_inspector_label,
            cluster_name.as_deref(),
            &access,
            None::<&jobs::NoopSink>,
        )
        .await
    {
        Ok(results) => {
            println!("{}", "✅ 完成".bright_green());
            results
        }
        Err(e) => {
            println!("{}", "❌ 失败".bright_red());
            eprintln!("错误: {}", e);
            return Err(e);
        }
    };

    println!();
    println!("{}", "📊 摘要:".bright_yellow().bold());
    println!(
        "   总体评分: {} {:.1}/100",
        if results.overall_score >= 90.0 {
            "🟢"
        } else if results.overall_score >= 80.0 {
            "🟡"
        } else if results.overall_score >= 70.0 {
            "🟠"
        } else {
            "🔴"
        },
        results.overall_score
    );

    let total_issues: usize = results
        .inspections
        .iter()
        .map(|i| i.summary.issues.len())
        .sum();

    println!(
        "   发现的问题: {}",
        if total_issues == 0 {
            format!("{}", total_issues).bright_green()
        } else {
            format!("{}", total_issues).bright_yellow()
        }
    );

    let output_path = output_path_with_extension(output, &results, format);
    let lang = results_lang(&results, lang);

    print!("📝 正在生成报告... ");
    match format {
        ReportFormat::Json => {
            let file = std::fs::File::create(&output_path)?;
            serde_json::to_writer_pretty(file, &results)?;
            println!("{}", "✅ 完成".bright_green());
            println!();
            println!("{}", "🎉 巡检成功完成!".bright_green().bold());
            println!("   报告: {}", output_path.bright_cyan());
        }
        ReportFormat::Csv => {
            let generator = ReportGenerator::with_lang(lang);
            let check_level_filter = Some(parse_check_level_filter(&level));
            let md_string = generator.generate_markdown_string(
                &results,
                None,
                None,
                None,
                check_level_filter,
            )?;
            let csv_content = reporting::md_export::md_to_csv(&md_string)?;
            std::fs::write(&output_path, csv_content)?;
            println!("{}", "✅ 完成".bright_green());
            println!();
            println!("{}", "🎉 巡检成功完成!".bright_green().bold());
            println!("   报告: {}", output_path.bright_cyan());
        }
        ReportFormat::Html => {
            let generator = ReportGenerator::with_lang(lang);
            let check_level_filter = Some(parse_check_level_filter(&level));
            let md_string = generator.generate_markdown_string(
                &results,
                None,
                None,
                None,
                check_level_filter,
            )?;
            let html_content = reporting::md_export::md_to_html(&md_string, lang)?;
            std::fs::write(&output_path, html_content)?;
            println!("{}", "✅ 完成".bright_green());
            println!();
            println!("{}", "🎉 巡检成功完成!".bright_green().bold());
            println!("   报告: {}", output_path.bright_cyan());
        }
        ReportFormat::Md => {
            let generator = ReportGenerator::with_lang(lang);
            let check_level_filter = Some(parse_check_level_filter(&level));
            generator
                .generate_report_with_filters(
                    &results,
                    &output_path,
                    None,
                    true,
                    None,
                    None,
                    check_level_filter,
                )
                .await?;
            println!("{}", "✅ 完成".bright_green());
            println!();
            println!("{}", "🎉 巡检成功完成!".bright_green().bold());
            println!("   报告: {}", output_path.bright_cyan());
        }
    }
    Ok(())
}

/// 从命令行 lang 确定报告语言（保留原逻辑）。
fn results_lang(_report: &ClusterReport, lang: Lang) -> Lang {
    lang
}
