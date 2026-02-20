//! Custom error types with proper HTTP status code mappings.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// API error response format
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApiError {
    #[schema(example = "Validation error: field is required")]
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "[\"name: validation failed\"]")]
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
            DomainError::ValidationErrors(details) => ApiError {
                error: "Validation failed".to_string(),
                details: Some(details.clone()),
            },
            _ => ApiError {
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

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use serde_json::Value;
    use validator::Validate;

    use super::*;

    #[derive(Debug, Validate)]
    struct ValidationFixture {
        #[validate(length(min = 1))]
        name: String,
    }

    #[test]
    fn status_code_mapping_matches_error_variants() {
        assert_eq!(
            DomainError::Validation("x".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            DomainError::ValidationErrors(vec!["x".to_string()]).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            DomainError::NotFound("x".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            DomainError::Unauthorized("x".to_string()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            DomainError::Forbidden("x".to_string()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            DomainError::Conflict("x".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            DomainError::BusinessLogic("x".to_string()).status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            DomainError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            DomainError::Database("x".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn into_response_includes_validation_error_details() {
        tokio_test::block_on(async {
            let response =
                DomainError::ValidationErrors(vec!["field: bad".to_string()]).into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("response body should be readable");
            let json: Value = serde_json::from_slice(&body).expect("body should be valid json");

            assert_eq!(json["error"], "Validation failed");
            assert_eq!(json["details"][0], "field: bad");
        });
    }

    #[test]
    fn into_response_uses_display_message_for_simple_errors() {
        tokio_test::block_on(async {
            let response = DomainError::NotFound("Pack missing".to_string()).into_response();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);

            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("response body should be readable");
            let json: Value = serde_json::from_slice(&body).expect("body should be valid json");
            assert_eq!(json["error"], "Resource not found: Pack missing");
            assert!(json["details"].is_null());
        });
    }

    #[test]
    fn from_validation_errors_maps_field_messages() {
        let errors = ValidationFixture {
            name: "".to_string(),
        }
        .validate()
        .expect_err("fixture should fail validation");

        let domain_error = DomainError::from_validation_errors(errors);
        match domain_error {
            DomainError::ValidationErrors(messages) => {
                assert!(!messages.is_empty());
                assert!(messages[0].contains("name"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn from_sqlx_error_maps_to_database_variant() {
        let err = sqlx::Error::Protocol("protocol violation".to_string());
        let mapped = DomainError::from(err);

        match mapped {
            DomainError::Database(message) => assert!(message.contains("protocol violation")),
            other => panic!("expected database error, got: {other:?}"),
        }
    }
}
