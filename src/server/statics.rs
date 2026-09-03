//! 内嵌前端静态资源托管（rust-embed）。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/"]
struct Asset;

fn content_type(name: &str) -> &'static str {
    if name.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if name.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if name.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if name.ends_with(".svg") {
        "image/svg+xml"
    } else if name.ends_with(".png") {
        "image/png"
    } else if name.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn serve(name: &str) -> Response {
    match Asset::get(name) {
        Some(file) => {
            let body = file.data.into_owned();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, content_type(name))],
                body,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn index() -> Response {
    serve("index.html")
}

pub async fn app_css() -> Response {
    serve("app.css")
}

pub async fn app_js() -> Response {
    serve("app.js")
}

pub async fn favicon() -> Response {
    serve("favicon.svg")
}

pub async fn logo() -> Response {
    serve("logo.png")
}
