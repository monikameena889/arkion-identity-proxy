//! Uniform JSON error responses: `{"error": {"code": "...", "message": "..."}, "request_id": "..."}`.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub fn error_response(status: StatusCode, code: &str, message: &str, request_id: &str) -> Response {
    let body = json!({ "error": { "code": code, "message": message }, "request_id": request_id });
    (status, Json(body)).into_response()
}

pub fn with_retry_after(mut resp: Response, secs: u64) -> Response {
    resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
    resp
}

/// Ask the client to close the connection (used when the connection's identity is no longer valid).
pub fn with_connection_close(mut resp: Response) -> Response {
    resp.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}
