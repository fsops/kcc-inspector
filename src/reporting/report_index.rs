//! 报告索引：管理报告目录下已生成的报告元数据（列表 / 下载 / 删除）。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub id: String,
    pub cluster: String,
    pub time: String,
    pub score: f64,
    pub format: String,
    /// 布尔值：目录下是否还有其它格式
    pub file_name: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ReportStore {
    dir: PathBuf,
    index_path: PathBuf,
    index: Arc<Mutex<Vec<ReportMeta>>>,
}

impl ReportStore {
    pub fn new(dir: &Path) -> Result<Self> {
        let dir = dir.to_path_buf();
        let index_path = dir.join("index.json");
        fs::create_dir_all(&dir).ok();
        let index = if index_path.exists() {
            let content = fs::read_to_string(&index_path).unwrap_or_else(|_| "[]".into());
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Self {
            dir,
            index_path,
            index: Arc::new(Mutex::new(index)),
        })
    }

    pub fn file_path(&self, file_name: &str) -> PathBuf {
        self.dir.join(file_name)
    }

    pub async fn list(&self) -> Vec<ReportMeta> {
        let mut index = self.index.lock().await;
        index.sort_by(|a, b| b.time.cmp(&a.time));
        index.clone()
    }

    pub async fn get(&self, id: &str) -> Option<ReportMeta> {
        self.index.lock().await.iter().find(|m| m.id == id).cloned()
    }

    pub async fn add(&self, meta: ReportMeta) {
        let mut index = self.index.lock().await;
        index.retain(|m| m.id != meta.id);
        index.push(meta);
        self.persist(&index).ok();
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        let mut index = self.index.lock().await;
        if let Some(pos) = index.iter().position(|m| m.id == id) {
            let meta = index.remove(pos);
            let fp = self.dir.join(&meta.file_name);
            let _ = fs::remove_file(&fp);
            // 同步删除同 id 的其它格式文件
            let others: Vec<_> = index
                .iter()
                .filter(|m| m.id == id)
                .map(|m| m.file_name.clone())
                .collect();
            for f in others {
                let _ = fs::remove_file(self.dir.join(f));
                index.retain(|m| m.id != id);
            }
            self.persist(&index)?;
        }
        Ok(())
    }

    fn persist(&self, index: &[ReportMeta]) -> Result<()> {
        let content = serde_json::to_string_pretty(index).context("serialize report index")?;
        fs::write(&self.index_path, content)?;
        Ok(())
    }
}
