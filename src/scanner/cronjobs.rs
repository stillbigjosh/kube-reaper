use anyhow::Result;
use k8s_openapi::api::batch::v1::CronJob;
use kube::{api::ListParams, Api};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CronJobInfo {
    pub name: String,
    pub namespace: String,
    pub schedule: String,
    pub service_account: String,
    pub image: String,
    pub suspended: bool,
}

pub async fn enumerate_cronjobs(
    client: &kube::Client,
    namespace: &str,
) -> Result<Vec<CronJobInfo>> {
    let api: Api<CronJob> = Api::namespaced(client.clone(), namespace);
    let list = api.list(&ListParams::default()).await?;

    let mut results = Vec::new();
    for cj in list.items {
        let spec = match cj.spec {
            Some(s) => s,
            None => continue,
        };

        let template_spec = spec
            .job_template
            .spec
            .and_then(|js| js.template.spec);

        let (sa, image) = match &template_spec {
            Some(ps) => {
                let sa = ps
                    .service_account_name
                    .as_deref()
                    .unwrap_or("default")
                    .to_string();
                let image = ps
                    .containers
                    .first()
                    .and_then(|c| c.image.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                (sa, image)
            }
            None => ("default".to_string(), "unknown".to_string()),
        };

        results.push(CronJobInfo {
            name: cj.metadata.name.unwrap_or_default(),
            namespace: namespace.to_string(),
            schedule: spec.schedule,
            service_account: sa,
            image,
            suspended: spec.suspend.unwrap_or(false),
        });
    }

    Ok(results)
}
