//! Strongly-typed domain identifiers and primitives.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable user identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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
