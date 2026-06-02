//! `DynamoDB` client configuration.
//!
//! Configures the AWS SDK for `DynamoDB` access, including region,
//! custom endpoint (for `LocalStack` / `DynamoDB` Local), and optional
//! table name prefix for multi-tenant deployments.

use serde::{Deserialize, Serialize};

/// `DynamoDB` configuration.
///
/// Can be loaded from the `"dynamodb"` section of `AppConfig`,
/// or from environment variables via `from_env()`.
///
/// Unlike the SQL database config, there is no connection URL —
/// `DynamoDB` uses the standard AWS SDK config chain (region,
/// credentials, endpoint override for `LocalStack`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DynamoConfig {
    /// AWS region for the `DynamoDB` client.
    #[serde(default = "default_region")]
    pub region: String,

    /// Custom endpoint URL (for `LocalStack` or `DynamoDB` Local).
    /// When set, overrides the default AWS endpoint.
    #[serde(default)]
    pub endpoint_url: Option<String>,

    /// Default table name prefix for multi-tenant setups.
    #[serde(default)]
    pub table_prefix: Option<String>,
}

fn default_region() -> String {
    std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-east-1".to_string())
}

impl Default for DynamoConfig {
    fn default() -> Self {
        Self {
            region: default_region(),
            endpoint_url: None,
            table_prefix: None,
        }
    }
}

impl DynamoConfig {
    /// Load from environment variables.
    ///
    /// - `AWS_REGION` or `AWS_DEFAULT_REGION` — region (default: us-east-1)
    /// - `DYNAMODB_ENDPOINT_URL` — custom endpoint (for `LocalStack`)
    /// - `DYNAMODB_TABLE_PREFIX` — optional table name prefix
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            region: default_region(),
            endpoint_url: std::env::var("DYNAMODB_ENDPOINT_URL").ok(),
            table_prefix: std::env::var("DYNAMODB_TABLE_PREFIX").ok(),
        }
    }

    /// Build the AWS SDK config from this `DynamoDB` config.
    pub async fn build_aws_config(&self) -> aws_config::SdkConfig {
        let mut builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(self.region.clone()));

        if let Some(ref endpoint) = self.endpoint_url {
            builder = builder.endpoint_url(endpoint);
        }

        builder.load().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_region() {
        let cfg = DynamoConfig::default();
        assert!(!cfg.region.is_empty());
        assert!(cfg.endpoint_url.is_none());
        assert!(cfg.table_prefix.is_none());
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = DynamoConfig {
            region: "eu-west-1".to_string(),
            endpoint_url: Some("http://localhost:4566".to_string()),
            table_prefix: Some("myapp_".to_string()),
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: DynamoConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.region, "eu-west-1");
        assert_eq!(
            parsed.endpoint_url.as_deref(),
            Some("http://localhost:4566")
        );
        assert_eq!(parsed.table_prefix.as_deref(), Some("myapp_"));
    }

    #[test]
    fn from_env_reads_defaults() {
        let cfg = DynamoConfig::from_env();
        assert!(!cfg.region.is_empty());
    }
}
