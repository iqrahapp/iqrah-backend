//! Strongly-typed domain identifiers and primitives.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable user identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
pub struct UserId(pub Uuid);

impl Display for UserId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Uuid> for UserId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<UserId> for Uuid {
    fn from(value: UserId) -> Self {
        value.0
    }
}

/// Stable device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "f47ac10b-58cc-4372-a567-0e02b2c3d479")]
pub struct DeviceId(pub Uuid);

impl Display for DeviceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Uuid> for DeviceId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<DeviceId> for Uuid {
    fn from(value: DeviceId) -> Self {
        value.0
    }
}

/// Stable pack identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "translation.en")]
pub struct PackId(pub String);

impl Display for PackId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for PackId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for PackId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<PackId> for String {
    fn from(value: PackId) -> Self {
        value.0
    }
}

/// Stable goal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "daily_goals")]
pub struct GoalId(pub String);

impl Display for GoalId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for GoalId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<GoalId> for String {
    fn from(value: GoalId) -> Self {
        value.0
    }
}

/// JWT subject claim value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "google-oauth-subject")]
pub struct JwtSubject(pub String);

impl Display for JwtSubject {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for JwtSubject {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for JwtSubject {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Error for invalid JWT subjects.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("JWT subject cannot be empty")]
pub struct JwtSubjectError;

impl JwtSubject {
    /// Creates a subject and rejects blank values.
    pub fn new(value: impl Into<String>) -> Result<Self, JwtSubjectError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(JwtSubjectError);
        }
        Ok(Self(value))
    }
}

impl AsRef<str> for JwtSubject {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<JwtSubject> for String {
    fn from(value: JwtSubject) -> Self {
        value.0
    }
}

/// Millisecond unix timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(value_type = i64, example = 1706000000000_i64)]
pub struct TimestampMs(pub i64);

impl Display for TimestampMs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<i64> for TimestampMs {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<TimestampMs> for i64 {
    fn from(value: TimestampMs) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use rstest::rstest;
    use serde::{Serialize, de::DeserializeOwned};
    use uuid::Uuid;

    use super::*;

    fn assert_serde_roundtrip<T>(value: T)
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let json = serde_json::to_string(&value).expect("serialize should succeed");
        let decoded: T = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(decoded, value);
    }

    #[test]
    fn user_id_supports_conversion_display_and_serde() {
        let raw = Uuid::new_v4();
        let user_id = UserId::from(raw);
        assert_eq!(user_id.to_string(), raw.to_string());
        assert_eq!(Uuid::from(user_id), raw);
        assert_serde_roundtrip(user_id);
    }

    #[test]
    fn device_id_supports_conversion_display_and_serde() {
        let raw = Uuid::new_v4();
        let device_id = DeviceId::from(raw);
        assert_eq!(device_id.to_string(), raw.to_string());
        assert_eq!(Uuid::from(device_id), raw);
        assert_serde_roundtrip(device_id);
    }

    #[test]
    fn pack_id_supports_conversions_display_and_serde() {
        let id_from_string = PackId::from("pack.en.v1".to_string());
        let id_from_str = PackId::from("pack.en.v1");
        assert_eq!(id_from_string, id_from_str);
        assert_eq!(id_from_string.to_string(), "pack.en.v1");
        assert_eq!(
            String::from(id_from_string.clone()),
            "pack.en.v1".to_string()
        );
        assert_serde_roundtrip(id_from_string);
    }

    #[test]
    fn goal_id_supports_conversions_display_and_serde() {
        let goal = GoalId::from("daily_goal".to_string());
        assert_eq!(goal.to_string(), "daily_goal");
        assert_eq!(String::from(goal.clone()), "daily_goal".to_string());
        assert_serde_roundtrip(goal);
    }

    #[test]
    fn timestamp_ms_supports_conversions_display_and_serde() {
        let ts = TimestampMs::from(1_706_000_000_000_i64);
        assert_eq!(ts.to_string(), "1706000000000");
        assert_eq!(i64::from(ts), 1_706_000_000_000_i64);
        assert_serde_roundtrip(ts);
    }

    #[rstest]
    #[case("sub-1")]
    #[case("google-oauth-subject")]
    #[case("subject-with-spaces")]
    fn jwt_subject_try_from_accepts_non_empty_values(#[case] value: &str) {
        let subject = JwtSubject::new(value).expect("non-empty values should be accepted");
        assert_eq!(subject.as_ref(), value);
        assert_eq!(subject.to_string(), value);
        assert_serde_roundtrip(subject);
    }

    #[rstest]
    #[case("")]
    #[case(" ")]
    #[case("\t\n")]
    fn jwt_subject_try_from_rejects_blank_values(#[case] value: &str) {
        let err = JwtSubject::new(value).expect_err("blank values should be rejected");
        assert_eq!(err, JwtSubjectError);
    }
}
