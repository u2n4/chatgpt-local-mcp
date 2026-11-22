use bridge_adapters::mcp::{ToolCostClass, tool_cost_class};
use bridge_types::{BridgeError, ErrorCode, OriginLayer, Principal};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[derive(Clone, Copy)]
pub enum Lane {
    Control,
    Read,
    Heavy,
}

impl Lane {
    pub fn for_tool(tool: &str) -> Self {
        match tool_cost_class(tool) {
            ToolCostClass::Control => Self::Control,
            ToolCostClass::Read => Self::Read,
            ToolCostClass::Heavy => Self::Heavy,
        }
    }

    pub fn for_frame(frame: &Value) -> Self {
        if frame.get("method").and_then(Value::as_str) == Some("tools/call") {
            Self::for_tool(
                frame
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )
        } else {
            Self::Read
        }
    }
}

struct Pool {
    outstanding: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    subject_outstanding: [Arc<Semaphore>; 3],
    subject_workers: [Arc<Semaphore>; 3],
    max_outstanding: usize,
    max_workers: usize,
    wait: Duration,
}

impl Pool {
    fn new(
        workers: usize,
        outstanding: usize,
        per_subject: usize,
        per_subject_total: usize,
        wait_ms: u64,
    ) -> Self {
        Self {
            outstanding: Arc::new(Semaphore::new(outstanding)),
            workers: Arc::new(Semaphore::new(workers)),
            subject_outstanding: std::array::from_fn(|_| {
                Arc::new(Semaphore::new(per_subject_total))
            }),
            subject_workers: std::array::from_fn(|_| Arc::new(Semaphore::new(per_subject))),
            max_outstanding: outstanding,
            max_workers: workers,
            wait: Duration::from_millis(wait_ms),
        }
    }

    fn snapshot(&self) -> Value {
        let active = self.max_workers - self.workers.available_permits();
        let admitted = self.max_outstanding - self.outstanding.available_permits();
        json!({
            "active": active,
            "queued": admitted.saturating_sub(active),
            "max_active": self.max_workers,
            "max_outstanding": self.max_outstanding,
        })
    }
}

pub struct Admission {
    control: Arc<Pool>,
    read: Arc<Pool>,
    heavy: Arc<Pool>,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            control: Arc::new(Pool::new(4, 24, 3, 16, 120)),
            read: Arc::new(Pool::new(8, 32, 6, 24, 300)),
            heavy: Arc::new(Pool::new(4, 16, 3, 8, 300)),
        }
    }
}

impl Admission {
    pub fn snapshot(&self) -> Value {
        json!({
            "control": self.control.snapshot(),
            "read": self.read.snapshot(),
            "heavy": self.heavy.snapshot(),
        })
    }

    pub async fn run<T, F>(
        &self,
        lane: Lane,
        principal: &Principal,
        work: F,
    ) -> Result<(T, Duration), BridgeError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let pool = Arc::clone(match lane {
            Lane::Control => &self.control,
            Lane::Read => &self.read,
            Lane::Heavy => &self.heavy,
        });
        // HTTP has three fixed authenticated identities. A new connection or a
        // caller-provided request/agent id does not create a fresh quota.
        let subject = match principal {
            Principal::Local => 0,
            Principal::Edge | Principal::PairedHost(_) => 1,
            Principal::DelegatedExecutor(_) => 2,
        };
        let queued_at = Instant::now();
        let subject_slot = Arc::clone(&pool.subject_outstanding[subject])
            .try_acquire_owned()
            .map_err(|_| busy("principal_limit"))?;
        let global_slot = Arc::clone(&pool.outstanding)
            .try_acquire_owned()
            .map_err(|_| busy("lane_limit"))?;
        let workers = tokio::time::timeout(pool.wait, async {
            let subject_worker = Arc::clone(&pool.subject_workers[subject])
                .acquire_owned()
                .await
                .ok()?;
            let global_worker = Arc::clone(&pool.workers).acquire_owned().await.ok()?;
            Some((subject_worker, global_worker))
        })
        .await
        .ok()
        .flatten()
        .ok_or_else(|| busy("queue_deadline"))?;
        // The blocking closure owns its permits even when its HTTP waiter is
        // disconnected. Dropping a JoinHandle does not cancel started work.
        tokio::task::spawn_blocking(move || {
            let _permits = (subject_slot, global_slot, workers);
            let wait = queued_at.elapsed();
            (work(), wait)
        })
        .await
        .map_err(|_| {
            BridgeError::new(
                ErrorCode::InternalError,
                "The blocking request worker failed.",
                OriginLayer::Transport,
            )
        })
    }
}

fn busy(reason: &str) -> BridgeError {
    BridgeError::new(
        ErrorCode::ResourceBusy,
        "Request capacity is temporarily exhausted.",
        OriginLayer::Transport,
    )
    .with_details(json!({"retry_after_ms": 150, "reason": reason}))
}
