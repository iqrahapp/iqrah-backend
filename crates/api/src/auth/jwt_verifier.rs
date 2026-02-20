//! Google JWT verification with cached JWKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

use iqrah_backend_domain::JwtSubject;

#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct GoogleJwk {
    kid: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleIdTokenClaims {
    sub: String,
}

/// Trait boundary for Google ID token verification.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait JwtVerifier: Send + Sync {
    /// Verifies an ID token and returns the JWT subject.
    async fn verify_google_id_token(&self, id_token: &str) -> anyhow::Result<JwtSubject>;
}

/// JWKS-backed Google ID token verifier.
#[derive(Clone)]
pub struct GoogleJwtVerifier {
    client: Client,
    google_client_id: String,
    jwks_by_kid: Arc<RwLock<HashMap<String, GoogleJwk>>>,
}

impl GoogleJwtVerifier {
    /// Creates a verifier and fetches JWKS immediately.
    pub async fn new(client: Client, google_client_id: String) -> anyhow::Result<Self> {
        let verifier = Self {
            client,
            google_client_id,
            jwks_by_kid: Arc::new(RwLock::new(HashMap::new())),
        };
        verifier.refresh_jwks().await?;
        Ok(verifier)
    }

    /// Starts a background JWKS refresh loop.
    pub fn spawn_refresh_task(self: Arc<Self>, period: Duration) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            loop {
                interval.tick().await;
                if let Err(error) = self.refresh_jwks().await {
                    tracing::warn!(error = %error, "Failed to refresh Google JWKS cache");
                }
            }
        });
    }

    async fn refresh_jwks(&self) -> anyhow::Result<()> {
        let response = self
            .client
            .get("https://www.googleapis.com/oauth2/v3/certs")
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<GoogleJwks>().await?;

        let mut map = HashMap::with_capacity(body.keys.len());
        for key in body.keys {
            map.insert(key.kid.clone(), key);
        }

        let mut cache = self.jwks_by_kid.write().await;
        *cache = map;
        Ok(())
    }
}

#[async_trait]
impl JwtVerifier for GoogleJwtVerifier {
    async fn verify_google_id_token(&self, id_token: &str) -> anyhow::Result<JwtSubject> {
        let header = decode_header(id_token)?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("Google ID token missing `kid` header"))?;
        let algorithm = header.alg;

        let key = {
            let cache = self.jwks_by_kid.read().await;
            cache.get(&kid).cloned()
        }
        .ok_or_else(|| anyhow::anyhow!("No matching Google JWKS key for kid `{kid}`"))?;

        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[self.google_client_id.as_str()]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        let decoding_key = match algorithm {
            Algorithm::RS256 => {
                let n = key.n.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Google JWKS key `{kid}` missing RSA modulus")
                })?;
                let e = key.e.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Google JWKS key `{kid}` missing RSA exponent")
                })?;
                DecodingKey::from_rsa_components(n, e)?
            }
            Algorithm::ES256 => {
                let x = key.x.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Google JWKS key `{kid}` missing EC x coordinate")
                })?;
                let y = key.y.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Google JWKS key `{kid}` missing EC y coordinate")
                })?;
                DecodingKey::from_ec_components(x, y)?
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported Google ID token algorithm: {algorithm:?}"
                ));
            }
        };
        let token = decode::<GoogleIdTokenClaims>(id_token, &decoding_key, &validation)?;

        if token.claims.sub.trim().is_empty() {
            return Err(anyhow::anyhow!("Google ID token subject is empty"));
        }

        Ok(JwtSubject(token.claims.sub))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;
    use tokio::sync::RwLock;

    use super::*;

    const RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTL
UTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2V
rUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8H
oGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBI
Mc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/
by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQABAoIBAHREk0I0O9DvECKd
WUpAmF3mY7oY9PNQiu44Yaf+AoSuyRpRUGTMIgc3u3eivOE8ALX0BmYUO5JtuRNZ
Dpvt4SAwqCnVUinIf6C+eH/wSurCpapSM0BAHp4aOA7igptyOMgMPYBHNA1e9A7j
E0dCxKWMl3DSWNyjQTk4zeRGEAEfbNjHrq6YCtjHSZSLmWiG80hnfnYos9hOr5Jn
LnyS7ZmFE/5P3XVrxLc/tQ5zum0R4cbrgzHiQP5RgfxGJaEi7XcgherCCOgurJSS
bYH29Gz8u5fFbS+Yg8s+OiCss3cs1rSgJ9/eHZuzGEdUZVARH6hVMjSuwvqVTFaE
8AgtleECgYEA+uLMn4kNqHlJS2A5uAnCkj90ZxEtNm3E8hAxUrhssktY5XSOAPBl
xyf5RuRGIImGtUVIr4HuJSa5TX48n3Vdt9MYCprO/iYl6moNRSPt5qowIIOJmIjY
2mqPDfDt/zw+fcDD3lmCJrFlzcnh0uea1CohxEbQnL3cypeLt+WbU6kCgYEAzSp1
9m1ajieFkqgoB0YTpt/OroDx38vvI5unInJlEeOjQ+oIAQdN2wpxBvTrRorMU6P0
7mFUbt1j+Co6CbNiw+X8HcCaqYLR5clbJOOWNR36PuzOpQLkfK8woupBxzW9B8gZ
mY8rB1mbJ+/WTPrEJy6YGmIEBkWylQ2VpW8O4O0CgYEApdbvvfFBlwD9YxbrcGz7
MeNCFbMz+MucqQntIKoKJ91ImPxvtc0y6e/Rhnv0oyNlaUOwJVu0yNgNG117w0g4
t/+Q38mvVC5xV7/cn7x9UMFk6MkqVir3dYGEqIl/OP1grY2Tq9HtB5iyG9L8NIam
QOLMyUqqMUILxdthHyFmiGkCgYEAn9+PjpjGMPHxL0gj8Q8VbzsFtou6b1deIRRA
2CHmSltltR1gYVTMwXxQeUhPMmgkMqUXzs4/WijgpthY44hK1TaZEKIuoxrS70nJ
4WQLf5a9k1065fDsFZD6yGjdGxvwEmlGMZgTwqV7t1I4X0Ilqhav5hcs5apYL7gn
PYPeRz0CgYALHCj/Ji8XSsDoF/MhVhnGdIs2P99NNdmo3R2Pv0CuZbDKMU559LJH
UvrKS8WkuWRDuKrz1W/EQKApFjDGpdqToZqriUFQzwy7mR3ayIiogzNtHcvbDHx8
oFnGY0OFksX/ye0/XGpy2SFxYRwGU98HPYeBvAQQrVjdkzfy7BmXQQ==
-----END RSA PRIVATE KEY-----"#;

    const RSA_N: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
    const RSA_E: &str = "AQAB";

    const EC_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
-----END PRIVATE KEY-----"#;

    const EC_X: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
    const EC_Y: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        aud: &'a str,
        iss: &'a str,
        exp: usize,
        iat: usize,
    }

    fn now_secs() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_secs() as usize
    }

    fn build_verifier(client_id: &str, keys: Vec<GoogleJwk>) -> GoogleJwtVerifier {
        let mut cache = HashMap::new();
        for key in keys {
            cache.insert(key.kid.clone(), key);
        }
        GoogleJwtVerifier {
            client: Client::new(),
            google_client_id: client_id.to_string(),
            jwks_by_kid: Arc::new(RwLock::new(cache)),
        }
    }

    fn encode_rs256_token(kid: &str, aud: &str, iss: &str, exp: usize) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &TestClaims {
                sub: "google-sub",
                aud,
                iss,
                exp,
                iat: now_secs().saturating_sub(10),
            },
            &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())
                .expect("rsa key should parse"),
        )
        .expect("token should encode")
    }

    fn encode_es256_token(kid: &str, aud: &str, iss: &str, exp: usize) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &TestClaims {
                sub: "google-sub",
                aud,
                iss,
                exp,
                iat: now_secs().saturating_sub(10),
            },
            &EncodingKey::from_ec_pem(EC_PRIVATE_KEY_PEM.as_bytes()).expect("ec key should parse"),
        )
        .expect("token should encode")
    }

    #[tokio::test]
    async fn verify_google_id_token_accepts_valid_rs256_token() {
        let verifier = build_verifier(
            "client-id",
            vec![GoogleJwk {
                kid: "rsa-kid".to_string(),
                n: Some(RSA_N.to_string()),
                e: Some(RSA_E.to_string()),
                x: None,
                y: None,
            }],
        );
        let token = encode_rs256_token(
            "rsa-kid",
            "client-id",
            "https://accounts.google.com",
            now_secs() + 120,
        );

        let subject = verifier
            .verify_google_id_token(&token)
            .await
            .expect("valid token should pass");

        assert_eq!(subject.as_ref(), "google-sub");
    }

    #[tokio::test]
    async fn verify_google_id_token_accepts_valid_es256_token() {
        let verifier = build_verifier(
            "client-id",
            vec![GoogleJwk {
                kid: "ec-kid".to_string(),
                n: None,
                e: None,
                x: Some(EC_X.to_string()),
                y: Some(EC_Y.to_string()),
            }],
        );
        let token = encode_es256_token(
            "ec-kid",
            "client-id",
            "https://accounts.google.com",
            now_secs() + 120,
        );

        let subject = verifier
            .verify_google_id_token(&token)
            .await
            .expect("valid token should pass");

        assert_eq!(subject.as_ref(), "google-sub");
    }

    #[tokio::test]
    async fn verify_google_id_token_rejects_wrong_audience() {
        let verifier = build_verifier(
            "client-id",
            vec![GoogleJwk {
                kid: "rsa-kid".to_string(),
                n: Some(RSA_N.to_string()),
                e: Some(RSA_E.to_string()),
                x: None,
                y: None,
            }],
        );
        let token = encode_rs256_token(
            "rsa-kid",
            "other-client-id",
            "https://accounts.google.com",
            now_secs() + 120,
        );

        let err = verifier
            .verify_google_id_token(&token)
            .await
            .expect_err("wrong audience should fail");
        assert!(err.to_string().to_lowercase().contains("aud"));
    }

    #[tokio::test]
    async fn verify_google_id_token_rejects_wrong_issuer() {
        let verifier = build_verifier(
            "client-id",
            vec![GoogleJwk {
                kid: "rsa-kid".to_string(),
                n: Some(RSA_N.to_string()),
                e: Some(RSA_E.to_string()),
                x: None,
                y: None,
            }],
        );
        let token = encode_rs256_token(
            "rsa-kid",
            "client-id",
            "https://bad-issuer",
            now_secs() + 120,
        );

        let err = verifier
            .verify_google_id_token(&token)
            .await
            .expect_err("wrong issuer should fail");
        assert!(err.to_string().to_lowercase().contains("issuer"));
    }

    #[tokio::test]
    async fn verify_google_id_token_rejects_expired_token() {
        let verifier = build_verifier(
            "client-id",
            vec![GoogleJwk {
                kid: "rsa-kid".to_string(),
                n: Some(RSA_N.to_string()),
                e: Some(RSA_E.to_string()),
                x: None,
                y: None,
            }],
        );
        let token = encode_rs256_token(
            "rsa-kid",
            "client-id",
            "https://accounts.google.com",
            now_secs().saturating_sub(120),
        );

        let err = verifier
            .verify_google_id_token(&token)
            .await
            .expect_err("expired token should fail");
        assert!(err.to_string().to_lowercase().contains("expired"));
    }

    #[tokio::test]
    async fn verify_google_id_token_rejects_unknown_kid() {
        let verifier = build_verifier("client-id", Vec::new());
        let token = encode_rs256_token(
            "unknown-kid",
            "client-id",
            "https://accounts.google.com",
            now_secs() + 120,
        );

        let err = verifier
            .verify_google_id_token(&token)
            .await
            .expect_err("unknown kid should fail");
        assert!(err.to_string().contains("No matching Google JWKS key"));
    }
}
