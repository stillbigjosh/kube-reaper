use anyhow::Result;
use k8s_openapi::api::core::v1::Service;
use kube::{api::ListParams, Api};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub cluster_ip: String,
    pub ports: Vec<ServicePort>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServicePort {
    pub port: i32,
    pub protocol: String,
    pub node_port: Option<i32>,
}

pub async fn enumerate_services(
    client: &kube::Client,
    namespace: &str,
) -> Result<Vec<ServiceInfo>> {
    let api: Api<Service> = Api::namespaced(client.clone(), namespace);
    let list = api.list(&ListParams::default()).await?;

    let mut results = Vec::new();
    for svc in list.items {
        let spec = match &svc.spec {
            Some(s) => s,
            None => continue,
        };

        let service_type = spec.type_.as_deref().unwrap_or("ClusterIP").to_string();
        let cluster_ip = spec.cluster_ip.as_deref().unwrap_or("None").to_string();

        let ports = spec
            .ports
            .as_ref()
            .map(|port_list| {
                port_list
                    .iter()
                    .map(|p| ServicePort {
                        port: p.port,
                        protocol: p.protocol.as_deref().unwrap_or("TCP").to_string(),
                        node_port: p.node_port,
                    })
                    .collect()
            })
            .unwrap_or_default();

        results.push(ServiceInfo {
            name: svc.metadata.name.unwrap_or_default(),
            namespace: namespace.to_string(),
            service_type,
            cluster_ip,
            ports,
        });
    }

    Ok(results)
}
