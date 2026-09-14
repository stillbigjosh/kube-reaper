use anyhow::Result;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ListParams};
use kube::Client;
use std::collections::HashMap;

use super::NamespaceInfo;

const PSS_ENFORCE_LABEL: &str = "pod-security.kubernetes.io/enforce";
const PSS_AUDIT_LABEL: &str = "pod-security.kubernetes.io/audit";
const PSS_WARN_LABEL: &str = "pod-security.kubernetes.io/warn";

pub async fn enumerate_namespaces(client: &Client) -> Result<Vec<NamespaceInfo>> {
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let namespaces = ns_api.list(&ListParams::default()).await?;

    let mut results = Vec::new();

    for ns in namespaces.items {
        let name = ns.metadata.name.unwrap_or_default();
        let btree_labels = ns.metadata.labels.unwrap_or_default();

        let pss_enforce = btree_labels.get(PSS_ENFORCE_LABEL).cloned();
        let pss_audit = btree_labels.get(PSS_AUDIT_LABEL).cloned();
        let pss_warn = btree_labels.get(PSS_WARN_LABEL).cloned();

        let labels: HashMap<String, String> = btree_labels.into_iter().collect();

        results.push(NamespaceInfo {
            name,
            pss_enforce,
            pss_audit,
            pss_warn,
            labels,
            service_accounts: Vec::new(),
        });
    }

    Ok(results)
}
