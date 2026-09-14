use anyhow::{Context, Result};
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::SelfSubjectRulesReview;
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::api::{Api, ListParams, PostParams};
use kube::Client;

use super::{NamespacePermissions, PermissionRule};

pub async fn get_current_identity(client: &Client) -> Result<String> {
    let ssr_api: Api<SelfSubjectReview> = Api::all(client.clone());
    let ssr = SelfSubjectReview {
        metadata: Default::default(),
        status: None,
    };

    match ssr_api.create(&PostParams::default(), &ssr).await {
        Ok(result) => {
            if let Some(status) = result.status {
                if let Some(user_info) = status.user_info {
                    return Ok(user_info.username.unwrap_or_else(|| "unknown".to_string()));
                }
            }
            Ok("unknown".to_string())
        }
        Err(_) => Ok("unknown (SelfSubjectReview not supported)".to_string()),
    }
}

pub async fn get_permissions_in_namespace(
    client: &Client,
    namespace: &str,
) -> Result<NamespacePermissions> {
    let ssrr_api: Api<SelfSubjectRulesReview> = Api::all(client.clone());
    let review = SelfSubjectRulesReview {
        metadata: Default::default(),
        spec: k8s_openapi::api::authorization::v1::SelfSubjectRulesReviewSpec {
            namespace: Some(namespace.to_string()),
        },
        status: None,
    };

    let result = ssrr_api
        .create(&PostParams::default(), &review)
        .await
        .context(format!(
            "Failed to enumerate permissions in namespace {}",
            namespace
        ))?;

    let mut rules = Vec::new();

    if let Some(status) = result.status {
        for rule in status.resource_rules {
            let verbs = rule.verbs;
            let resources = rule.resources.unwrap_or_default();
            let api_groups = rule.api_groups.unwrap_or_default();
            let resource_names = rule.resource_names.unwrap_or_default();

            for resource in &resources {
                for api_group in &api_groups {
                    rules.push(PermissionRule {
                        resource: resource.clone(),
                        api_group: api_group.clone(),
                        verbs: verbs.clone(),
                        resource_names: resource_names.clone(),
                    });
                }
            }
        }
    }

    Ok(NamespacePermissions {
        namespace: namespace.to_string(),
        rules,
    })
}

pub async fn get_service_accounts(client: &Client, namespace: &str) -> Result<Vec<String>> {
    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    let list = sa_api.list(&ListParams::default()).await?;
    Ok(list
        .items
        .iter()
        .filter_map(|sa| sa.metadata.name.clone())
        .collect())
}
