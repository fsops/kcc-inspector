use anyhow::Result;
use http::Request;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::CronJob;
use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use k8s_openapi::api::core::v1::{
    Event, Namespace, Node, PersistentVolume, PersistentVolumeClaim, Pod, Secret, Service,
};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::config::Kubeconfig;
use kube::{Api, Client, Config};
use serde::Deserialize;

fn infer_cluster_name() -> Option<String> {
    let kubeconfig = Kubeconfig::read().ok()?;
    let current = kubeconfig.current_context.as_ref()?;
    let named = kubeconfig.contexts.iter().find(|nc| nc.name == *current)?;
    let ctx = named.context.as_ref()?;
    Some(ctx.cluster.clone())
}

#[derive(Clone)]
pub struct K8sClient {
    client: Client,
    cluster_name: Option<String>,
}

impl K8sClient {
    pub async fn new(config_file: Option<&str>) -> Result<Self> {
        if let Some(path) = config_file {
            std::env::set_var("KUBECONFIG", path);
        }
        let cluster_name = infer_cluster_name();
        let config = Config::infer().await?;
        let client = Client::try_from(config)?;
        Ok(Self {
            client,
            cluster_name,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Cluster name from kubeconfig current context, or None if in-cluster or unset.
    pub fn cluster_name(&self) -> Option<&str> {
        self.cluster_name.as_deref()
    }

    // Node APIs
    pub fn nodes(&self) -> Api<Node> {
        Api::all(self.client.clone())
    }

    // Pod APIs
    pub fn pods(&self, namespace: Option<&str>) -> Api<Pod> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Deployment APIs
    pub fn deployments(&self, namespace: Option<&str>) -> Api<Deployment> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Storage APIs
    pub fn persistent_volumes(&self) -> Api<PersistentVolume> {
        Api::all(self.client.clone())
    }

    pub fn persistent_volume_claims(&self, namespace: Option<&str>) -> Api<PersistentVolumeClaim> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    pub fn storage_classes(&self) -> Api<StorageClass> {
        Api::all(self.client.clone())
    }

    // Service APIs
    pub fn services(&self, namespace: Option<&str>) -> Api<Service> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Network APIs
    pub fn network_policies(&self, namespace: Option<&str>) -> Api<NetworkPolicy> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Autoscaling APIs
    pub fn horizontal_pod_autoscalers(
        &self,
        namespace: Option<&str>,
    ) -> Api<HorizontalPodAutoscaler> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Batch APIs
    pub fn cron_jobs(&self, namespace: Option<&str>) -> Api<CronJob> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Certificates API (CSR)
    pub fn certificate_signing_requests(&self) -> Api<CertificateSigningRequest> {
        Api::all(self.client.clone())
    }

    pub fn secrets(&self, namespace: Option<&str>) -> Api<Secret> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // RBAC APIs
    #[allow(dead_code)]
    pub fn roles(&self, namespace: Option<&str>) -> Api<Role> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    #[allow(dead_code)]
    pub fn role_bindings(&self, namespace: Option<&str>) -> Api<RoleBinding> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    pub fn cluster_roles(&self) -> Api<ClusterRole> {
        Api::all(self.client.clone())
    }

    pub fn cluster_role_bindings(&self) -> Api<ClusterRoleBinding> {
        Api::all(self.client.clone())
    }

    // Namespace API
    pub fn namespaces(&self) -> Api<Namespace> {
        Api::all(self.client.clone())
    }

    // Events API (namespaced)
    #[allow(dead_code)]
    pub fn events(&self, namespace: Option<&str>) -> Api<Event> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    // Other workload APIs
    #[allow(dead_code)]
    pub fn replica_sets(&self, namespace: Option<&str>) -> Api<ReplicaSet> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    pub fn daemon_sets(&self, namespace: Option<&str>) -> Api<DaemonSet> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    pub fn stateful_sets(&self, namespace: Option<&str>) -> Api<StatefulSet> {
        match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    /// Returns the Kubernetes API server version (e.g. "v1.28.0") if available.
    /// Uses the apiserver /version endpoint (gitVersion).
    pub async fn server_version(&self) -> Result<Option<String>> {
        let info = self.client.apiserver_version().await?;
        Ok(Some(info.git_version))
    }

    /// Fetches node metrics from metrics.k8s.io/v1beta1 (requires metrics-server).
    /// Returns list of (node_name, cpu_usage_str, memory_usage_str) or None if API unavailable.
    pub async fn node_metrics(&self) -> Result<Option<Vec<(String, String, String)>>> {
        let req = Request::builder()
            .method("GET")
            .uri("/apis/metrics.k8s.io/v1beta1/nodes")
            .body(vec![])
            .map_err(|e| anyhow::anyhow!("build request: {}", e))?;
        let list: NodeMetricsList = match self.client.request(req).await {
            Ok(l) => l,
            Err(_) => return Ok(None),
        };
        let out: Vec<(String, String, String)> = list
            .items
            .into_iter()
            .map(|m| {
                let name = m.metadata.name;
                let cpu = m
                    .usage
                    .get("cpu")
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                let memory = m
                    .usage
                    .get("memory")
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                (name, cpu, memory)
            })
            .collect();
        Ok(Some(out))
    }

    /// Fetches pod metrics from metrics.k8s.io/v1beta1 (requires metrics-server).
    /// Returns list of (namespace, pod_name, container_name, cpu_usage_str, memory_usage_str) or None if API unavailable.
    pub async fn pod_metrics(
        &self,
    ) -> Result<Option<Vec<(String, String, String, String, String)>>> {
        let req = Request::builder()
            .method("GET")
            .uri("/apis/metrics.k8s.io/v1beta1/pods")
            .body(vec![])
            .map_err(|e| anyhow::anyhow!("build request: {}", e))?;
        let list: PodMetricsList = match self.client.request(req).await {
            Ok(l) => l,
            Err(_) => return Ok(None),
        };
        let mut out = Vec::new();
        for pm in list.items {
            let namespace = pm.metadata.namespace.unwrap_or_default();
            let pod_name = pm.metadata.name;
            for c in pm.containers {
                let cpu = c
                    .usage
                    .get("cpu")
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                let memory = c
                    .usage
                    .get("memory")
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                out.push((namespace.clone(), pod_name.clone(), c.name, cpu, memory));
            }
        }
        Ok(Some(out))
    }
}

#[derive(Deserialize)]
struct NodeMetricsList {
    items: Vec<NodeMetrics>,
}

#[derive(Deserialize)]
struct NodeMetrics {
    metadata: NodeMetricsMeta,
    usage: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct NodeMetricsMeta {
    name: String,
}

#[derive(Deserialize)]
struct PodMetricsList {
    items: Vec<PodMetrics>,
}

#[derive(Deserialize)]
struct PodMetrics {
    metadata: PodMetricsMeta,
    containers: Vec<ContainerMetrics>,
}

#[derive(Deserialize)]
struct PodMetricsMeta {
    name: String,
    #[serde(default)]
    namespace: Option<String>,
}

#[derive(Deserialize)]
struct ContainerMetrics {
    name: String,
    usage: std::collections::HashMap<String, String>,
}
