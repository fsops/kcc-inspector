//! kcc 集中配置：server / node-inspector / 节点采集 / 报告 / 认证。
//! 支持 `kcc.yaml` 环境变量与代码内置默认值，优先级：参数 > 环境变量 > 配置文件 > 默认值。

use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

/// 节点采集访问方式
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeAccessMode {
    /// 主程序直接访问每个节点巡检 Pod 的 IP（默认，主程序与 Pod 同集群）
    #[default]
    PodIp,
    /// 预留：通过 ClusterIP / Headless Service 访问（当前按 PodIP 处理）
    ClusterIpService,
}

impl std::fmt::Display for NodeAccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeAccessMode::PodIp => write!(f, "pod_ip"),
            NodeAccessMode::ClusterIpService => write!(f, "cluster_ip_service"),
        }
    }
}

impl std::str::FromStr for NodeAccessMode {
    type Err = ();

    /// 解析 "pod_ip" / "cluster_ip_service"（含常见别名）。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "pod_ip" | "podip" | "pod" => Ok(NodeAccessMode::PodIp),
            "cluster_ip_service" | "service" => Ok(NodeAccessMode::ClusterIpService),
            _ => Err(()),
        }
    }
}

/// 节点采集选项
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NodeAccess {
    /// pod_ip | cluster_ip_service
    pub mode: NodeAccessMode,
    /// 节点巡检程序端口
    pub port: u16,
    /// Pod 访问超时（秒）
    pub timeout_secs: u64,
}

impl Default for NodeAccess {
    fn default() -> Self {
        Self {
            mode: NodeAccessMode::PodIp,
            port: 9090,
            timeout_secs: 30,
        }
    }
}

/// 认证配置
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// 是否启用登录认证（false 后所有 API 公开访问，适用于内网/调试环境）
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,
    /// JWT 签名密钥（优先使用环境变量 KCC_AUTH_SECRET）
    pub secret: String,
    /// token 有效期（秒）
    pub token_ttl_secs: u64,
    /// 账号列表（password 为 argon2 哈希；留空则启动时创建默认 admin）
    pub users: Vec<UserConfig>,
}

/// 认证开关默认开启（缺失配置项时也保持开启，保证安全）
fn default_auth_enabled() -> bool {
    true
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            secret: String::new(),
            token_ttl_secs: 28800,
            users: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password_hash: String,
}

/// 完整配置
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 主程序 HTTP + Web 监听地址
    pub server_addr: String,
    /// Web / API 前缀（默认 /kcc，nginx 据此路径代理）
    pub web_base: String,
    /// 节点巡检程序监听地址
    pub node_inspector_addr: String,
    /// 节点程序读取宿主机的根目录（DaemonSet 挂载 /host）
    pub node_host_root: String,
    /// 主程序查找节点巡检 DaemonSet 的命名空间（默认 kube-system，部署方可自行决定）
    pub node_inspector_namespace: String,
    /// 节点巡检 Pod 的选择标签（等价 KCC_INSPECTOR_LABEL）
    pub node_inspector_label: String,
    /// 节点采集方式
    pub node_access: NodeAccess,
    /// 报告输出目录
    pub reports_dir: PathBuf,
    /// 默认报告格式（md/json/csv/html）
    pub default_format: String,
    /// 默认报告语言（zh/en），等价 KCC_DEFAULT_LANG
    pub default_lang: String,
    /// 默认问题分级（all 或逗号分隔的 info,warning,critical），等价 KCC_DEFAULT_LEVEL
    pub default_level: String,
    /// kubeconfig 文件路径（等价 --kubeconfig 参数；参数优先，其次环境变量 KCC_KUBECONFIG）
    pub kubeconfig: Option<String>,
    /// 执行记录 / 日志目录
    pub logs_dir: PathBuf,
    /// 认证配置
    pub auth: AuthConfig,
}

impl Default for Config {
    fn default() -> Self {
        let secret = std::env::var("KCC_AUTH_SECRET")
            .unwrap_or_else(|_| "change-me-kcc-super-secret".to_string());
        let users = {
            // 未配置账号时，用 KCC_ADMIN_USER（默认 admin）/ KCC_ADMIN_PASSWORD（默认 admin）在启动时创建默认账号
            let uname = std::env::var("KCC_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
            let pw = std::env::var("KCC_ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_string());
            if !pw.is_empty() {
                let hash = hash_password(&pw);
                vec![UserConfig {
                    username: uname,
                    password_hash: hash,
                }]
            } else {
                Vec::new()
            }
        };
        Self {
            server_addr: "0.0.0.0:5005".to_string(),
            web_base: "/kcc".to_string(),
            node_inspector_addr: "0.0.0.0:9090".to_string(),
            node_host_root: "/host".to_string(),
            node_inspector_namespace: "kube-system".to_string(),
            node_inspector_label: "app=kcc-inspector".to_string(),
            node_access: NodeAccess::default(),
            reports_dir: PathBuf::from("./reports"),
            default_format: "html".to_string(),
            default_lang: "zh".to_string(),
            default_level: "warning,critical".to_string(),
            kubeconfig: None,
            logs_dir: PathBuf::from("./logs"),
            auth: AuthConfig {
                enabled: true,
                secret,
                token_ttl_secs: 28800,
                users,
            },
        }
    }
}

impl Config {
    /// 从配置文件加载并叠加环境变量。
    pub fn load(path: Option<&str>) -> Result<Config> {
        if let Some(p) = path {
            let content = std::fs::read_to_string(p)?;
            let mut cfg: Config = serde_yaml::from_str(&content)?;
            cfg.apply_env();
            return Ok(cfg);
        }
        let mut cfg = Config::default();
        cfg.apply_env();
        Ok(cfg)
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("KCC_SERVER_ADDR") {
            self.server_addr = v;
        }
        if let Ok(v) = std::env::var("KCC_WEB_BASE") {
            self.web_base = v.trim_end_matches('/').to_string();
        }
        if let Ok(v) = std::env::var("KCC_NODE_INSPECTOR_ADDR") {
            self.node_inspector_addr = v;
        }
        if let Ok(v) = std::env::var("KCC_HOST_ROOT") {
            self.node_host_root = v;
        }
        if let Ok(v) = std::env::var("KCC_INSPECTOR_NAMESPACE") {
            self.node_inspector_namespace = v;
        }
        if let Ok(v) = std::env::var("KCC_INSPECTOR_LABEL") {
            self.node_inspector_label = v;
        }
        if let Ok(v) = std::env::var("KCC_NODE_ACCESS_PORT") {
            if let Ok(p) = v.parse() {
                self.node_access.port = p;
            }
        }
        if let Ok(v) = std::env::var("KCC_NODE_ACCESS_MODE") {
            if let Ok(m) = v.parse() {
                self.node_access.mode = m;
            }
        }
        if let Ok(v) = std::env::var("KCC_REPORTS_DIR") {
            self.reports_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("KCC_LOGS_DIR") {
            self.logs_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("KCC_DEFAULT_FORMAT") {
            self.default_format = v;
        }
        if let Ok(v) = std::env::var("KCC_DEFAULT_LANG") {
            self.default_lang = v;
        }
        if let Ok(v) = std::env::var("KCC_DEFAULT_LEVEL") {
            self.default_level = v;
        }
        if let Ok(v) = std::env::var("KCC_KUBECONFIG") {
            self.kubeconfig = Some(v);
        }
        if let Ok(v) = std::env::var("KCC_AUTH_ENABLED") {
            self.auth.enabled = matches!(
                v.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
    }
}

/// 使用 argon2 对明文密码哈希，返回 PHC 字符串。
pub fn hash_password(plain: &str) -> String {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| format!("${}$", plain))
}

/// 校验明文密码与 argon2 哈希是否匹配。
pub fn verify_password(plain: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    // 非 PHC 哈希（如旧配置明文兜底）直接比较
    if !hash.starts_with("$argon2") {
        return plain == hash;
    }
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}
