//! Custom error types with proper HTTP status code mappings.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// API error response format
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
}

/// Domain errors with HTTP status code mappings
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    /// Validation error (400 Bad Request)
    #[error("Validation error: {0}")]
    Validation(String),

    /// Multiple validation errors (400 Bad Request)
    #[error("Validation failed")]
    ValidationErrors(Vec<String>),

    /// Resource not found (404 Not Found)
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Unauthorized (401 Unauthorized)
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden (403 Forbidden)
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Conflict (409 Conflict)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Unprocessable entity - business logic error (422 Unprocessable Entity)
    #[error("Business logic error: {0}")]
    BusinessLogic(String),

    /// Rate limit exceeded (429 Too Many Requests)
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Internal server error (500 Internal Server Error)
    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),

    /// Database error (500 Internal Server Error)
    #[error("Database error")]
    Database(String),
}

impl DomainError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            DomainError::Validation(_) | DomainError::ValidationErrors(_) => {
                StatusCode::BAD_REQUEST
            }
            DomainError::NotFound(_) => StatusCode::NOT_FOUND,
            DomainError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            DomainError::Forbidden(_) => StatusCode::FORBIDDEN,
            DomainError::Conflict(_) => StatusCode::CONFLICT,
            DomainError::BusinessLogic(_) => StatusCode::UNPROCESSABLE_ENTITY,
            DomainError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            DomainError::Internal(_) | DomainError::Database(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Create a validation error from validator errors
    pub fn from_validation_errors(errors: validator::ValidationErrors) -> Self {
        let messages: Vec<String> = errors
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |error| {
                    format!(
                        "{}: {}",
                        field,
                        error
                            .message
                            .as_ref()
                            .unwrap_or(&std::borrow::Cow::Borrowed("validation failed"))
                    )
                })
            })
            .collect();

        if messages.is_empty() {
            DomainError::Validation("Invalid input".to_string())
        } else {
            DomainError::ValidationErrors(messages)
        }
    }
}

/// Implement IntoResponse for DomainError to integrate with Axum
impl IntoResponse for DomainError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // Log internal errors
        if matches!(self, DomainError::Internal(_) | DomainError::Database(_)) {
            tracing::error!("Internal error: {}", self);
        }

        let body = match &self {
            DomainError::ValidationErrors(details) => ErrorResponse {
                error: "Validation failed".to_string(),
                details: Some(details.clone()),
            },
            _ => ErrorResponse {
                error: self.to_string(),
                details: None,
            },
        };

        (status, Json(body)).into_response()
    }
}

/// Helper to convert anyhow errors to DomainError
impl From<sqlx::Error> for DomainError {
    fn from(err: sqlx::Error) -> Self {
        DomainError::Database(err.to_string())
    }
}
