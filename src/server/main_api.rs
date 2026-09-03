//! 主程序 HTTP API：巡检触发/状态/日志/SSE、报告列表/下载/删除。

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;

use crate::cli::{InspectionType, ReportFormat};
use crate::jobs::{JobProgressSink, JobStatus, ProgressSink};
use crate::reporting::generator::parse_check_level_filter;
use crate::reporting::report_index::ReportMeta;
use crate::reporting::ReportGenerator;
use crate::server::auth::ApiError;
use crate::server::AppState;
use crate::utils::lang::Lang;
use uuid::Uuid;

/// 巡检请求体
#[derive(Debug, Deserialize)]
pub struct InspectRequest {
    pub types: Option<Vec<String>>,
    pub namespace: Option<String>,
    pub format: Option<String>,
    pub lang: Option<String>,
    pub level: Option<String>,
    pub node_inspector_namespace: Option<String>,
    /// 报告标题中显示的集群名称（等价于 CLI 的 --cluster-name，留空自动识别）
    pub cluster_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CursorQuery {
    pub cursor: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct FormatQuery {
    pub format: Option<String>,
}

#[derive(Serialize)]
struct InspectStarted {
    inspect_id: String,
}

fn parse_inspection_type(s: &str) -> InspectionType {
    s.parse().unwrap_or(InspectionType::All)
}

fn parse_lang(s: &str) -> Lang {
    match s.to_lowercase().trim() {
        "en" => Lang::En,
        _ => Lang::Zh,
    }
}

// ---------------- 巡检 ----------------

pub async fn options(State(_state): State<AppState>) -> Json<serde_json::Value> {
    let types = [
        "all",
        "nodes",
        "pods",
        "resources",
        "network",
        "storage",
        "security",
        "control-plane",
        "autoscaling",
        "batch",
        "policies",
        "observability",
        "upgrade",
        "certificates",
    ];
    Json(serde_json::json!({
        "types": types,
        "formats": ["md", "json", "csv", "html"],
        "langs": ["zh", "en"],
        "levels": ["all", "warning,critical", "info,warning,critical"],
    }))
}

pub async fn create(State(state): State<AppState>, Json(req): Json<InspectRequest>) -> Response {
    let id = Uuid::new_v4().to_string();
    let types = req.types.clone().unwrap_or_else(|| vec!["all".to_string()]);
    let format = req
        .format
        .clone()
        .unwrap_or_else(|| state.cfg.default_format.clone());
    let lang = req
        .lang
        .clone()
        .unwrap_or_else(|| state.cfg.default_lang.clone());

    let job = crate::jobs::Job::new(id.clone(), types.clone(), format.clone(), lang.clone());
    state.jobs.insert(job).await;

    let task_id = id.clone();
    let level = req
        .level
        .clone()
        .unwrap_or_else(|| state.cfg.default_level.clone());
    let store = state.jobs.clone();
    let reports = state.reports.clone();
    let cfg = state.cfg.clone();
    let ns_override = req.node_inspector_namespace.clone();

    // panic 保护：tokio::spawn 会把任务内的 panic 捕获到 JoinHandle；
    // 监控任务 await 该 handle，若 panic 则把任务标记为失败，
    // 而不是让任务永久卡在 running（旧行为会导致前端一直轮询、进度停在 50%）。
    let store_watch = store.clone();
    let id_watch = task_id.clone();
    let handle = tokio::spawn(async move {
        {
            let sink = JobProgressSink::new(store.clone(), task_id.clone()).await;
            sink.status(JobStatus::Running);
            sink.log(format!("🚀 巡检任务 {} 已启动", task_id));

            let client = match crate::k8s::K8sClient::new(cfg.kubeconfig.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    sink.log(format!("❌ 连接集群失败: {}", e));
                    sink.status(JobStatus::Failed);
                    persist_run_record(&store, &task_id).await;
                    return;
                }
            };
            let runner =
                crate::inspections::InspectionRunner::new(client).with_lang(parse_lang(&lang));
            let inspection_type = types
                .first()
                .map(|s| parse_inspection_type(s))
                .unwrap_or(InspectionType::All);
            let node_ns = ns_override
                .clone()
                .unwrap_or_else(|| cfg.node_inspector_namespace.clone());
            let result = runner
                .run_inspections_ex(
                    inspection_type,
                    req.namespace.as_deref(),
                    &node_ns,
                    &cfg.node_inspector_label,
                    req.cluster_name.as_deref(),
                    &cfg.node_access,
                    Some(&sink),
                )
                .await;

            let report = match result {
                Ok(report) => report,
                Err(e) => {
                    if store.is_cancelled(&task_id).await {
                        sink.log("🛑 巡检已取消".to_string());
                        sink.status(JobStatus::Cancelled);
                    } else {
                        sink.log(format!("❌ 巡检失败: {}", e));
                        sink.status(JobStatus::Failed);
                    }
                    persist_run_record(&store, &task_id).await;
                    return;
                }
            };

            let meta = match generate_report(&reports, &report, &format, &level, &lang, &cfg).await
            {
                Ok(meta) => meta,
                Err(e) => {
                    sink.log(format!("❌ 报告生成失败: {}", e));
                    sink.status(JobStatus::Failed);
                    persist_run_record(&store, &task_id).await;
                    return;
                }
            };
            sink.log(format!("✅ 报告已生成：{}", meta.file_name));
            store.set_report_id(&task_id, meta.id.clone()).await;
            store.set_score(&task_id, report.overall_score).await;
            sink.set_score(report.overall_score);
            sink.log(format!("📊 总体评分：{:.1}/100", report.overall_score));
            sink.progress(100.0, 100, 100);
            sink.status(JobStatus::Completed);
            persist_run_record(&store, &task_id).await;
        }
    });
    // 监控任务：巡检任务 panic 时把状态标记为 failed，避免永久卡在 running
    tokio::spawn(async move {
        if handle.await.is_err() {
            let sink = JobProgressSink::new(store_watch.clone(), id_watch.clone()).await;
            sink.log("❌ 巡检内部错误（panic）导致任务异常终止".to_string());
            sink.status(JobStatus::Failed);
            persist_run_record(&store_watch, &id_watch).await;
        }
    });

    Json(InspectStarted { inspect_id: id }).into_response()
}

pub async fn status(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.jobs.get(&id).await {
        Some(j) => Json(serde_json::json!({
            "id": j.id,
            "status": j.status.as_str(),
            "progress": j.progress,
            "current": j.current,
            "total": j.total,
            "score": j.score,
            "report_id": j.report_id,
            "types": j.types,
            "format": j.format,
            "lang": j.lang,
            "started_at": j.started_at.to_rfc3339(),
            "finished_at": j.finished_at.map(|t| t.to_rfc3339()),
        }))
        .into_response(),
        None => ApiError::not_found("未找到该巡检任务".into()).into_response(),
    }
}

pub async fn logs(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<CursorQuery>,
) -> Response {
    match state.jobs.get(&id).await {
        Some(_) => {
            let (lines, cursor) = state.jobs.logs_since(&id, q.cursor.unwrap_or(0)).await;
            Json(serde_json::json!({ "logs": lines, "cursor": cursor })).into_response()
        }
        None => ApiError::not_found("未找到该巡检任务".into()).into_response(),
    }
}

/// SSE 实时推送巡检日志/状态（配合 /logs 轮询兜底）。
/// 关键：只在“发生变化”时推送事件——
/// 1) 终态事件只推送一次后立即关闭流；
/// 2) 进度事件仅当百分比变化才推送，避免在慢步骤(如节点采集)期间每 800ms
///    重发同一个 [进度] 事件，把日志刷爆、拖垮浏览器内存。
pub async fn stream_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let jobs = state.jobs.clone();
    // 状态四元组：任务 id、日志游标、是否已发送过终态事件、上次已推送的进度值
    let stream = futures::stream::unfold(
        (id.clone(), 0usize, false, f64::NAN),
        move |(jid, mut cursor, term_sent, last_progress)| {
            let jobs = jobs.clone();
            async move {
                // 终态事件已发送：立即结束流，避免无限重放
                if term_sent {
                    return None::<(Result<Event, Infallible>, _)>;
                }
                loop {
                    let (lines, new_cursor) = jobs.logs_since(&jid, cursor).await;
                    cursor = new_cursor;
                    let job = jobs.get(&jid).await;
                    let terminal = match &job {
                        Some(j) => matches!(
                            j.status,
                            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled
                        ),
                        None => true,
                    };
                    if let Some(j) = &job {
                        let st = j.status.as_str();
                        if st != "running" {
                            // 推送一次终态事件，并将状态置为“已发送，下次调用直接结束”
                            let ev = Event::default().data(format!("[状态] {}", st));
                            return Some((
                                Ok::<Event, Infallible>(ev),
                                (jid, cursor, true, last_progress),
                            ));
                        }
                    }
                    if terminal {
                        return None;
                    }
                    if let Some(line) = lines.into_iter().next() {
                        let ev = Event::default().data(line);
                        return Some((Ok(ev), (jid, cursor, false, last_progress)));
                    }
                    if let Some(j) = &job {
                        if j.progress > 0.0 && (j.progress - last_progress).abs() > 0.001 {
                            let ev = Event::default().data(format!(
                                "[进度] {:.0}% ({}/{})",
                                j.progress, j.current, j.total
                            ));
                            return Some((Ok(ev), (jid, cursor, false, j.progress)));
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(800)).await;
                }
            }
        },
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

pub async fn cancel(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if state.jobs.request_cancel(&id).await {
        state.jobs.append_log(&id, "🛑 收到取消请求".into()).await;
        Json(serde_json::json!({ "ok": true })).into_response()
    } else {
        ApiError::not_found("未找到该巡检任务".into()).into_response()
    }
}

pub async fn history(State(state): State<AppState>) -> Json<serde_json::Value> {
    let runs = state.jobs.history(200).await;
    Json(serde_json::json!({ "runs": runs }))
}

// ---------------- 报告 ----------------

pub async fn reports(State(state): State<AppState>) -> Json<serde_json::Value> {
    let list = state.reports.list().await;
    let items: Vec<serde_json::Value> = list
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "cluster": m.cluster,
                "time": m.time,
                "score": m.score,
                "format": m.format,
                "size": m.size,
                "name": m.file_name,
            })
        })
        .collect();
    Json(serde_json::json!({ "reports": items }))
}

pub async fn report_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<FormatQuery>,
) -> Response {
    let meta = match state.reports.get(&id).await {
        Some(m) => m,
        None => return ApiError::not_found("未找到该报告".into()).into_response(),
    };
    let fname = q
        .format
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| meta.file_name.clone());
    let fname = if state.reports.file_path(&fname).exists() {
        fname
    } else {
        meta.file_name.clone()
    };
    let path = state.reports.file_path(&fname);
    let body = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return ApiError::not_found("报告文件不存在".into()).into_response(),
    };
    let ct = match fname.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        _ => "text/markdown",
    };
    let disp = fname.clone();
    (
        [
            (header::CONTENT_TYPE, ct.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", disp),
            ),
        ],
        body,
    )
        .into_response()
}

pub async fn report_delete(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    state.reports.remove(&id).await.ok();
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ---------------- 节点状态 ----------------

pub async fn nodes_status(State(state): State<AppState>) -> Response {
    let ns = state.cfg.node_inspector_namespace.clone();
    let port = state.cfg.node_access.port;
    let timeout = state.cfg.node_access.timeout_secs;
    let client = match crate::k8s::K8sClient::new(state.cfg.kubeconfig.as_deref()).await {
        Ok(c) => c,
        Err(e) => return ApiError::internal("连接集群失败".into(), e).into_response(),
    };
    match crate::node_inspection::probe_node_endpoints_alive::<crate::jobs::NoopSink>(
        &client,
        &ns,
        port,
        timeout,
        None,
        &state.cfg.node_inspector_label,
    )
    .await
    {
        Ok(eps) => Json(serde_json::json!({
            "namespace": ns,
            "mode": state.cfg.node_access.mode.to_string(),
            "port": port,
            "endpoints": eps.iter().map(|e| serde_json::json!({
                "node_name": e.node_name,
                "pod_name": e.pod_name,
                "pod_ip": e.pod_ip,
                "alive": e.alive,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => ApiError::internal("查询节点巡检状态失败".into(), e).into_response(),
    }
}

// ---------------- 报告生成 ----------------

async fn generate_report(
    reports: &crate::reporting::report_index::ReportStore,
    report: &crate::inspections::types::ClusterReport,
    format: &str,
    level: &str,
    lang: &str,
    cfg: &crate::config::Config,
) -> anyhow::Result<ReportMeta> {
    let ts = report
        .display_timestamp_filename
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d-%H%M%S").to_string());
    let fname = format!("kubernetes-inspection-report-{}.{}", ts, format);
    let out_path = cfg.reports_dir.join(&fname);

    let fmt = match format {
        "json" => ReportFormat::Json,
        "csv" => ReportFormat::Csv,
        "html" => ReportFormat::Html,
        _ => ReportFormat::Md,
    };
    let gen_lang = parse_lang(lang);
    let generator = ReportGenerator::with_lang(gen_lang);
    let check_level = Some(parse_check_level_filter(level));

    match fmt {
        ReportFormat::Json => {
            let file = std::fs::File::create(&out_path)?;
            serde_json::to_writer_pretty(file, report)?;
        }
        ReportFormat::Csv => {
            let md = generator.generate_markdown_string(report, None, None, None, check_level)?;
            let csv = crate::reporting::md_export::md_to_csv(&md)?;
            std::fs::write(&out_path, csv)?;
        }
        ReportFormat::Html => {
            let md = generator.generate_markdown_string(report, None, None, None, check_level)?;
            let html = crate::reporting::md_export::md_to_html(&md, gen_lang)?;
            std::fs::write(&out_path, html)?;
        }
        ReportFormat::Md => {
            generator
                .generate_report_with_filters(
                    report,
                    &out_path.to_string_lossy(),
                    None,
                    true,
                    None,
                    None,
                    check_level,
                )
                .await?;
        }
    }

    let size = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    let meta = ReportMeta {
        id: report.report_id.clone(),
        cluster: report.cluster_name.clone(),
        time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        score: report.overall_score,
        format: format.to_string(),
        file_name: fname,
        size,
    };
    reports.add(meta.clone()).await;
    Ok(meta)
}

/// 把任务日志/进度落盘为执行记录文档（logs/runs/{id}.md）。
async fn persist_run_record(store: &crate::jobs::JobStore, id: &str) {
    let Some(job) = store.get(id).await else {
        return;
    };
    let dir = std::path::PathBuf::from("./logs/runs");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let (lines, _) = store.logs_since(id, 0).await;
    let mut md = format!(
        "# 巡检执行记录 `{}`\n\n- 类型：{}\n- 状态：{}\n- 得分：{}\n- 开始：{}\n- 耗时：{}s\n\n## 日志\n\n```\n{}\n```\n",
        job.id,
        job.types.join(", "),
        job.status.as_str(),
        job.score.map(|s| format!("{:.1}", s)).unwrap_or("-".into()),
        job.started_at.to_rfc3339(),
        job.duration_secs(),
        lines.join("\n"),
    );
    // 日志可能为空时补一行
    if lines.is_empty() {
        md.push_str("（无日志）\n");
    }
    let _ = std::fs::write(dir.join(format!("{}.md", id)), md);
}
