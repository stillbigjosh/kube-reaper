use anyhow::Result;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use kube::Client;

use super::SecretRef;

pub async fn enumerate_secrets(client: &Client, namespace: &str) -> Result<Vec<SecretRef>> {
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secrets = secret_api.list(&ListParams::default()).await?;

    let results = secrets
        .items
        .iter()
        .map(|s| SecretRef {
            name: s.metadata.name.clone().unwrap_or_default(),
            namespace: namespace.to_string(),
            secret_type: s.type_.clone().unwrap_or_else(|| "Opaque".to_string()),
        })
        .collect();

    Ok(results)
}
