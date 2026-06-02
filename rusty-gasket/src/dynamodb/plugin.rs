//! `DynamoDB` lifecycle plugin.
//!
//! Creates the AWS SDK `DynamoDB` client during `prepare` and stores it
//! in shared extensions for the [`DynamoClient`] extractor.

use rusty_gasket::BoxError;
use rusty_gasket::plugin::{
    LayerContext, Plugin, PluginOrdering, PrepareContext, ShutdownContext, TaggedLayer,
};

use rusty_gasket::dynamodb::config::DynamoConfig;
use rusty_gasket::dynamodb::extractor::DynamoClient;

/// Lifecycle plugin that creates and manages the `DynamoDB` client.
///
/// During `prepare`, reads `DynamoConfig` from the app config's
/// `"dynamodb"` section (or falls back to environment variables),
/// builds the AWS SDK config, and stores the client in shared
/// extensions for the `DynamoClient` extractor to find.
#[derive(Debug, Default)]
pub struct DynamoPlugin;

impl Plugin for DynamoPlugin {
    fn name(&self) -> &'static str {
        "gasket:dynamodb"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    async fn prepare(&self, ctx: &mut PrepareContext) -> Result<(), BoxError> {
        let dynamo_config: DynamoConfig = if ctx.config.has_section("dynamodb") {
            ctx.config.section("dynamodb")?
        } else {
            DynamoConfig::from_env()
        };

        let sdk_config = dynamo_config.build_aws_config().await;
        let client = aws_sdk_dynamodb::Client::new(&sdk_config);

        tracing::info!(
            region = %dynamo_config.region,
            endpoint = ?dynamo_config.endpoint_url,
            table_prefix = ?dynamo_config.table_prefix,
            "DynamoDB client created"
        );

        ctx.extensions.insert(DynamoClient(client));
        ctx.extensions.insert(dynamo_config);
        Ok(())
    }

    fn layers(&self, ctx: &LayerContext) -> Vec<TaggedLayer> {
        if let Some(client) = ctx.extensions.get::<DynamoClient>() {
            let client = client.clone();
            vec![TaggedLayer::new(
                rusty_gasket::pipeline::MiddlewareSlot::Custom,
                move |router: axum::Router| router.layer(axum::Extension(client)),
            )]
        } else {
            Vec::new()
        }
    }

    async fn shutdown(&self, _ctx: &ShutdownContext) -> Result<(), BoxError> {
        tracing::info!("DynamoDB plugin shutting down");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_name() {
        let plugin = DynamoPlugin;
        assert_eq!(plugin.name(), "gasket:dynamodb");
    }

    #[test]
    fn plugin_ordering() {
        let plugin = DynamoPlugin;
        let ordering = plugin.ordering();
        assert!(ordering.before.contains(&"gasket:server"));
    }
}
