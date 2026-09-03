//! kcc 服务端：NodeInspector HTTP API + kcc server（主程序 API + 内嵌 Web）。

pub mod auth;
pub mod main_api;
pub mod node_api;
pub mod statics;

use anyhow::Result;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

use crate::config::Config;
use crate::jobs::JobStore;
use crate::reporting::report_index::ReportStore;

/// 全局应用状态
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub jobs: Arc<JobStore>,
    pub reports: Arc<ReportStore>,
}

/// 装配 kcc server 的完整路由（主程序 API + 内嵌 Web）。
/// 顺序：公开路由（静态资源/登录）→ 鉴权中间件 → 需要登录的路由。
pub fn app(cfg: Config, jobs: Arc<JobStore>, reports: Arc<ReportStore>) -> Router {
    let root = cfg.web_base.trim_end_matches('/').to_string();
    let api = format!("{}/api", root);
    let state = AppState {
        cfg: Arc::new(cfg),
        jobs,
        reports,
    };

    let auth_mw = axum::middleware::from_fn_with_state(state.clone(), auth::require_auth);

    let router = Router::new()
        // ---- 内嵌 Web（公开） ----
        .route(&root, get(statics::index))
        .route(&format!("{}/", root), get(statics::index))
        .route(&format!("{}/static/app.css", root), get(statics::app_css))
        .route(&format!("{}/static/app.js", root), get(statics::app_js))
        .route(&format!("{}/favicon.svg", root), get(statics::favicon))
        .route(&format!("{}/logo.png", root), get(statics::logo))
        // ---- 认证（公开） ----
        .route(&format!("{}/auth/login", api), post(auth::login))
        .route(&format!("{}/auth/init", api), get(auth::init))
        // ---- 认证（需要登录） ----
        .route(&format!("{}/auth/me", api), get(auth::me))
        // 巡检
        .route(&format!("{}/inspect/options", api), get(main_api::options))
        .route(&format!("{}/inspect/history", api), get(main_api::history))
        .route(&format!("{}/inspect", api), post(main_api::create))
        .route(&format!("{}/inspect/:id", api), get(main_api::status))
        .route(&format!("{}/inspect/:id/logs", api), get(main_api::logs))
        .route(
            &format!("{}/inspect/:id/stream", api),
            get(main_api::stream_job),
        )
        .route(
            &format!("{}/inspect/:id/cancel", api),
            post(main_api::cancel),
        )
        // 报告
        .route(&format!("{}/reports", api), get(main_api::reports))
        .route(
            &format!("{}/reports/:id/download", api),
            get(main_api::report_download),
        )
        .route(
            &format!("{}/reports/:id", api),
            axum::routing::delete(main_api::report_delete),
        )
        // 节点状态
        .route(
            &format!("{}/nodes/inspector/status", api),
            get(main_api::nodes_status),
        )
        // 全局鉴权（公开路径在 require_auth 内白名单放行）：.layer 包裹此前注册的全部路由
        .layer(auth_mw);

    router.with_state(state)
}

/// 启动主程序 server（HTTP + Web）。
pub async fn serve(cfg: Config) -> Result<()> {
    let jobs = Arc::new(JobStore::new());
    let reports = Arc::new(ReportStore::new(&cfg.reports_dir)?);
    let router = app(cfg.clone(), jobs, reports);
    let listener = tokio::net::TcpListener::bind(&cfg.server_addr).await?;
    println!(
        "✅ kcc server 已启动: http://{}{}/",
        cfg.server_addr, cfg.web_base
    );
    println!(
        "   巡检配置: server={} node_inspector_ns={} 模式={}",
        cfg.server_addr, cfg.node_inspector_namespace, cfg.node_access.mode
    );
    axum::serve(listener, router).await?;
    Ok(())
}

/// 启动节点巡检程序（DaemonSet 守护，默认端口 9090）。
pub async fn serve_node(cfg: Config) -> Result<()> {
    let router = node_api::router(&cfg, &cfg.web_base);
    let listener = tokio::net::TcpListener::bind(&cfg.node_inspector_addr).await?;
    println!(
        "✅ node inspector 已启动: {} （{}）",
        cfg.node_inspector_addr, cfg.web_base
    );
    axum::serve(listener, router).await?;
    Ok(())
}
