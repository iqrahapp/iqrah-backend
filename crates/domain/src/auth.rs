//! Auth types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{JwtSubject, UserId};

/// Google OAuth login request.
#[derive(Debug, Deserialize)]
pub struct GoogleAuthRequest {
    pub id_token: String,
}

/// Auth response with access token.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub user_id: UserId,
    pub expires_in: u64,
}

/// User profile response.
#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: UserId,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// JWT claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: JwtSubject, // user_id
    pub exp: u64,        // expiration timestamp
    pub iat: u64,        // issued at
}
