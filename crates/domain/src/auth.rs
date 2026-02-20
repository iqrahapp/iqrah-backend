//! Auth types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{JwtSubject, UserId};

/// Google OAuth login request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct GoogleAuthRequest {
    #[schema(example = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9...")]
    pub id_token: String,
}

/// Auth response with access token.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuthResponse {
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub access_token: String,
    pub user_id: UserId,
    #[schema(example = 3600)]
    pub expires_in: u64,
}

/// User profile response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserProfile {
    pub id: UserId,
    #[schema(example = "2026-02-20T16:00:00Z")]
    pub created_at: DateTime<Utc>,
    #[schema(example = "2026-02-20T16:10:00Z")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// JWT claims.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Claims {
    pub sub: JwtSubject, // user_id
    #[schema(example = 1_900_000_000_u64)]
    pub exp: u64, // expiration timestamp
    #[schema(example = 1_899_996_400_u64)]
    pub iat: u64, // issued at
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn google_auth_request_deserializes_expected_id_token() {
        let raw = serde_json::json!({ "id_token": "google-token" });
        let request: GoogleAuthRequest =
            serde_json::from_value(raw).expect("request should deserialize");

        assert_eq!(request.id_token, "google-token");
    }

    #[test]
    fn claims_roundtrip_through_serde() {
        let claims = Claims {
            sub: JwtSubject::new("subject-123").expect("valid subject"),
            exp: 2_000_000_000,
            iat: 1_900_000_000,
        };

        let serialized = serde_json::to_string(&claims).expect("claims should serialize");
        let restored: Claims =
            serde_json::from_str(&serialized).expect("claims should deserialize");

        assert_eq!(restored.sub, claims.sub);
        assert_eq!(restored.exp, claims.exp);
        assert_eq!(restored.iat, claims.iat);
    }

    #[test]
    fn auth_response_serializes_with_user_id_and_expiry() {
        let response = AuthResponse {
            access_token: "token-abc".to_string(),
            user_id: UserId(Uuid::new_v4()),
            expires_in: 3600,
        };

        let value = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(value["expires_in"], 3600);
        assert_eq!(value["user_id"], response.user_id.to_string());
        assert_eq!(value["access_token"], response.access_token);
    }

    #[test]
    fn user_profile_serializes_nullable_last_seen() {
        let now = Utc::now();
        let profile = UserProfile {
            id: UserId(Uuid::new_v4()),
            created_at: now,
            last_seen_at: Some(now),
        };

        let value = serde_json::to_value(&profile).expect("profile should serialize");

        assert_eq!(value["id"], profile.id.to_string());
        assert!(value["created_at"].is_string());
        assert!(value["last_seen_at"].is_string());
    }
}
