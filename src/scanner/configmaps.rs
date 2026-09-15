use anyhow::Result;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{api::ListParams, Api};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ConfigMapRef {
    pub name: String,
    pub namespace: String,
    pub data_keys: Vec<String>,
    pub has_sensitive_keys: bool,
}

const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "connection",
    "dsn",
    "database_url",
    "db_url",
    "api_key",
    "apikey",
    "private_key",
    "auth",
    "mysql",
    "postgres",
    "redis_url",
    "mongodb",
    "smtp",
    "aws_",
    "azure_",
    "gcp_",
];

pub async fn enumerate_configmaps(
    client: &kube::Client,
    namespace: &str,
) -> Result<Vec<ConfigMapRef>> {
    let api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let list = api.list(&ListParams::default()).await?;

    let mut results = Vec::new();
    for cm in list.items {
        let name = cm.metadata.name.unwrap_or_default();

        let data_keys: Vec<String> = cm
            .data
            .as_ref()
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();

        let has_sensitive = data_keys.iter().any(|k| {
            let lower = k.to_lowercase();
            SENSITIVE_KEY_PATTERNS.iter().any(|p| lower.contains(p))
        }) || name_looks_sensitive(&name);

        results.push(ConfigMapRef {
            name,
            namespace: namespace.to_string(),
            data_keys,
            has_sensitive_keys: has_sensitive,
        });
    }

    Ok(results)
}

fn name_looks_sensitive(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("credential")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("auth-config")
        || lower.contains("database")
        || lower.contains("connection")
}
