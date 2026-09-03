//! 认证：账号密码登录（argon2 校验）+ JWT 签发 + 鉴权中间件。

use axum::body::Body;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::config::verify_password;
use crate::server::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

fn now_ts() -> usize {
    chrono::Utc::now().timestamp().max(0) as usize
}

/// 登录请求体
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// 登录响应
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

fn authenticate(state: &AppState, username: &str, password: &str) -> bool {
    state
        .cfg
        .auth
        .users
        .iter()
        .any(|u| u.username == username && verify_password(password, &u.password_hash))
}

/// 从 Authorization: Bearer <token> 中还原用户名。
pub fn verify_token(token: &str, state: &AppState) -> Option<String> {
    let token = token.strip_prefix("Bearer ")?;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.cfg.auth.secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?;
    Some(data.claims.sub)
}

/// POST /kcc/api/auth/login
pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    if !authenticate(&state, &req.username, &req.password) {
        return ApiError::unauthorized("用户名或密码错误".to_string()).into_response();
    }
    let ttl = state.cfg.auth.token_ttl_secs;
    let claims = Claims {
        sub: req.username.clone(),
        iat: now_ts(),
        exp: now_ts() + ttl as usize,
    };
    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.cfg.auth.secret.as_bytes()),
    ) {
        Ok(token) => Json(LoginResponse {
            token,
            username: req.username,
        })
        .into_response(),
        Err(e) => ApiError::internal("签发令牌失败".into(), e).into_response(),
    }
}

/// 全局鉴权中间件：仅对 API 前缀下的路径强制鉴权，登录与初始化探测直接放行，
/// 其余 API 必须携带有效 Bearer token，否则 401；非 API 路径（Web 静态页/favicon）放行。
pub async fn require_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // 认证开关关闭时（auth.enabled=false / KCC_AUTH_ENABLED=false），所有接口公开访问
    if !state.cfg.auth.enabled {
        return next.run(req).await;
    }
    let api = format!("{}/api", state.cfg.web_base.trim_end_matches('/'));
    let path = req.uri().path().to_string();

    // 非 API 路径（如 /favicon.ico、Web 静态页）不参与鉴权，直接放行交给路由处理
    if !path.starts_with(api.as_str()) {
        return next.run(req).await;
    }

    // API 内的公开路径
    if path == format!("{}/auth/login", api) || path == format!("{}/auth/init", api) {
        return next.run(req).await;
    }

    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if verify_token(token, &state).is_none() {
        return ApiError::unauthorized("认证失败：缺失或无效的令牌".to_string()).into_response();
    }
    next.run(req).await
}

/// GET /kcc/api/auth/me —— 返回当前登录用户
pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Json<serde_json::Value> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let username = verify_token(token, &state).unwrap_or_default();
    Json(serde_json::json!({
        "username": username,
        "authenticated": !username.is_empty(),
    }))
}

/// GET /kcc/api/auth/init —— 是否已初始化账号
pub async fn init(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "initialized": !state.cfg.auth.users.is_empty(),
        "user_count": state.cfg.auth.users.len(),
        "token_ttl_secs": state.cfg.auth.token_ttl_secs,
    }))
}

/// 统一 API 错误
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub detail: Option<String>,
}

impl ApiError {
    pub fn unauthorized(msg: String) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg,
            detail: None,
        }
    }
    pub fn not_found(msg: String) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg,
            detail: None,
        }
    }
    pub fn internal(msg: String, detail: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg,
            detail: Some(detail.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
            "detail": self.detail,
        }));
        (self.status, body).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::internal("服务器内部错误".to_string(), e)
    }
}
