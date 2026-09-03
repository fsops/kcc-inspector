//! 巡检任务模型：内存任务存储、日志缓冲、进度事件与历史记录。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// 任务状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Cancelled => "cancelled",
        }
    }
}

/// 单个巡检任务
#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub types: Vec<String>,
    pub format: String,
    pub lang: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: JobStatus,
    /// 0-100
    pub progress: f64,
    pub current: usize,
    pub total: usize,
    pub score: Option<f64>,
    /// 报告 id（完成后填充，位于报告索引中）
    pub report_id: Option<String>,
    /// 追加式日志行
    pub logs: Vec<String>,
    pub cancelled: bool,
}

impl Job {
    pub fn new(id: String, types: Vec<String>, format: String, lang: String) -> Self {
        Self {
            id,
            types,
            format,
            lang,
            started_at: Utc::now(),
            finished_at: None,
            status: JobStatus::Queued,
            progress: 0.0,
            current: 0,
            total: 0,
            score: None,
            report_id: None,
            logs: Vec::new(),
            cancelled: false,
        }
    }

    pub fn duration_secs(&self) -> i64 {
        let end = self.finished_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.started_at)
            .num_seconds()
            .max(0)
    }
}

/// 任务历史记录条目（供前端 /history）
#[derive(Debug, Clone, Serialize)]
pub struct RunRecord {
    pub id: String,
    pub types: Vec<String>,
    pub started_at: String,
    pub duration: String,
    pub status: String,
    pub score: Option<f64>,
}

/// 内存任务存储（单进程内，会话级）
#[derive(Debug, Clone, Default)]
pub struct JobStore {
    inner: Arc<Mutex<HashMap<String, Job>>>,
    cancel_flags: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl JobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(&self, job: Job) {
        self.inner.lock().await.insert(job.id.clone(), job.clone());
        self.cancel_flags
            .lock()
            .await
            .insert(job.id.clone(), Arc::new(AtomicBool::new(false)));
    }

    /// 返回任务对应的取消标志（可同步读取），用于协作式取消。
    pub async fn cancel_flag(&self, id: &str) -> Option<Arc<AtomicBool>> {
        self.cancel_flags.lock().await.get(id).cloned()
    }

    pub async fn is_cancelled(&self, id: &str) -> bool {
        self.cancel_flags
            .lock()
            .await
            .get(id)
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }

    pub async fn get(&self, id: &str) -> Option<Job> {
        self.inner.lock().await.get(id).cloned()
    }

    pub async fn append_log(&self, id: &str, line: String) {
        let mut m = self.inner.lock().await;
        if let Some(j) = m.get_mut(id) {
            for l in line.split('\n') {
                let l = l.trim_end();
                if !l.is_empty() {
                    j.logs.push(l.to_string());
                }
            }
        }
    }

    pub async fn set_status(&self, id: &str, status: JobStatus) {
        let mut m = self.inner.lock().await;
        if let Some(j) = m.get_mut(id) {
            j.status = status;
            if matches!(
                status,
                JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled
            ) {
                j.finished_at = Some(Utc::now());
            }
        }
    }

    pub async fn set_progress(&self, id: &str, pct: f64, current: usize, total: usize) {
        let mut m = self.inner.lock().await;
        if let Some(j) = m.get_mut(id) {
            j.progress = pct;
            j.current = current;
            j.total = total;
        }
    }

    pub async fn set_score(&self, id: &str, score: f64) {
        let mut m = self.inner.lock().await;
        if let Some(j) = m.get_mut(id) {
            j.score = Some(score);
        }
    }

    pub async fn set_report_id(&self, id: &str, report_id: String) {
        let mut m = self.inner.lock().await;
        if let Some(j) = m.get_mut(id) {
            j.report_id = Some(report_id);
        }
    }

    pub async fn request_cancel(&self, id: &str) -> bool {
        let mut m = self.inner.lock().await;
        if let Some(j) = m.get_mut(id) {
            j.cancelled = true;
            if let Some(f) = self.cancel_flags.lock().await.get(id) {
                f.store(true, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    pub async fn logs_since(&self, id: &str, cursor: usize) -> (Vec<String>, usize) {
        let m = self.inner.lock().await;
        match m.get(id) {
            Some(j) => {
                let total = j.logs.len();
                let start = cursor.min(total);
                (j.logs[start..].to_vec(), total)
            }
            None => (Vec::new(), cursor),
        }
    }

    pub async fn history(&self, limit: usize) -> Vec<RunRecord> {
        let m = self.inner.lock().await;
        let mut runs: Vec<RunRecord> = m
            .values()
            .map(|j| RunRecord {
                id: j.id.clone(),
                types: j.types.clone(),
                started_at: j.started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                duration: format!("{}s", j.duration_secs()),
                status: j.status.as_str().to_string(),
                score: j.score,
            })
            .collect();
        runs.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        runs.truncate(limit);
        runs
    }
}

/// 巡检过程的消费回调：主程序 API 用它把进度/日志实时推给前端（SSE/轮询）。
pub trait ProgressSink: Send + Sync {
    /// 输出一行日志
    fn log(&self, line: String);
    /// 更新状态
    fn status(&self, status: JobStatus);
    /// 更新进度（0-100、当前步、总步）
    fn progress(&self, pct: f64, current: usize, total: usize);
    /// 巡检是否被取消
    fn cancelled(&self) -> bool;
    /// 设置最终评分
    fn set_score(&self, score: f64);
}

/// 把进度写入 JobStore 的 Sink 实现
pub struct JobProgressSink {
    store: Arc<JobStore>,
    id: String,
    cancel: Arc<AtomicBool>,
}

impl JobProgressSink {
    pub async fn new(store: Arc<JobStore>, id: String) -> Self {
        let cancel = store
            .cancel_flag(&id)
            .await
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        Self { store, id, cancel }
    }
}

impl ProgressSink for JobProgressSink {
    fn log(&self, line: String) {
        let store = self.store.clone();
        let id = self.id.clone();
        tokio::spawn(async move { store.append_log(&id, line).await });
    }

    fn status(&self, status: JobStatus) {
        let store = self.store.clone();
        let id = self.id.clone();
        tokio::spawn(async move { store.set_status(&id, status).await });
    }

    fn progress(&self, pct: f64, current: usize, total: usize) {
        let store = self.store.clone();
        let id = self.id.clone();
        tokio::spawn(async move { store.set_progress(&id, pct, current, total).await });
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn set_score(&self, score: f64) {
        let store = self.store.clone();
        let id = self.id.clone();
        tokio::spawn(async move { store.set_score(&id, score).await });
    }
}

/// 不做任何事的 Sink（测试/占位）
pub struct NoopSink;

impl ProgressSink for NoopSink {
    fn log(&self, _line: String) {}
    fn status(&self, _status: JobStatus) {}
    fn progress(&self, _pct: f64, _current: usize, _total: usize) {}
    fn cancelled(&self) -> bool {
        false
    }
    fn set_score(&self, _score: f64) {}
}
