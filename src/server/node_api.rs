//! 节点巡检程序的 HTTP API（默认 9090），供主程序调用以触发/获取本节点巡检。

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use std::sync::Arc;

use crate::config::Config;
use crate::node_inspection::LocalCollector;

#[derive(Clone)]
pub struct NodeState {
    pub collector: LocalCollector,
    pub started_at: DateTime<Utc>,
    pub version: String,
}

/// 构建节点巡检程序路由（前缀可配置）
pub fn router(_cfg: &Config, root: &str) -> Router {
    let state = Arc::new(NodeState {
        collector: LocalCollector::from_env(),
        started_at: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    });
    let base = format!("{}/api", root);
    Router::new()
        .route(&format!("{}/health", base), get(health))
        .route(&format!("{}/inspect", base), get(inspect).post(inspect))
        .route(&format!("{}/inspect/status", base), get(status))
        .with_state(state)
}

/// GET /kcc/api/health
async fn health(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "node_name": state.collector.node_name(),
        "version": state.version,
        "ready": true,
        "uptime_secs": Utc::now().signed_duration_since(state.started_at).num_seconds(),
    }))
}

/// GET|POST /kcc/api/inspect —— 触发本节点巡检并返回 JSON
async fn inspect(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    Json(state.collector.collect())
}

/// GET /kcc/api/inspect/status —— 返回采集状态
async fn status(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "node_name": state.collector.node_name(),
        "last_collect_at": Utc::now().to_rfc3339(),
        "fresh": true,
    }))
}
