use bridge_adapters::mcp::{ToolCostClass, WaitCancel, tool_cost_class, with_wait_cancel};
use bridge_types::{BridgeError, ErrorCode, OriginLayer, Principal};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const MAX_CONCURRENT_WAITS_PER_CALLER: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Control,
    Read,
    ReadWait,
    Heavy,
}

impl Lane {
    pub fn for_tool(tool: &str) -> Self {
        if tool == "job_wait" {
            return Self::ReadWait;
        }
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
    wait_slots: [Arc<Semaphore>; 3],
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            control: Arc::new(Pool::new(4, 24, 3, 16, 120)),
            read: Arc::new(Pool::new(8, 32, 6, 24, 300)),
            heavy: Arc::new(Pool::new(4, 16, 3, 8, 300)),
            wait_slots: std::array::from_fn(|_| {
                Arc::new(Semaphore::new(MAX_CONCURRENT_WAITS_PER_CALLER))
            }),
        }
    }
}

struct CancelWaitOnDrop(WaitCancel);

impl Drop for CancelWaitOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
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
            Lane::Read | Lane::ReadWait => &self.read,
            Lane::Heavy => &self.heavy,
        });
        // HTTP has three fixed authenticated identities. A new connection or a
        // caller-provided request/agent id does not create a fresh quota.
        let subject = match principal {
            Principal::Local => 0,
            Principal::Edge | Principal::PairedHost(_) => 1,
            Principal::DelegatedExecutor(_) => 2,
        };
        let wait_permit = if lane == Lane::ReadWait && !principal.is_edge() {
            Some(
                Arc::clone(&self.wait_slots[subject])
                    .try_acquire_owned()
                    .map_err(|_| wait_busy())?,
            )
        } else {
            None
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
        // Dropping this future (e.g. HTTP client disconnect) signals any waiting
        // `job_wait` call to exit immediately and release its permits.
        let cancel = WaitCancel::new();
        let _cancel_on_drop = CancelWaitOnDrop(cancel.clone());
        tokio::task::spawn_blocking(move || {
            let _permits = (wait_permit, subject_slot, global_slot, workers);
            let wait = queued_at.elapsed();
            let result = if lane == Lane::ReadWait {
                with_wait_cancel(cancel, work)
            } else {
                work()
            };
            (result, wait)
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

fn wait_busy() -> BridgeError {
    BridgeError::new(
        ErrorCode::ResourceBusy,
        "At most 2 concurrent job_wait calls are allowed per caller.",
        OriginLayer::Transport,
    )
    .with_details(json!({"retry_after_ms": 500, "reason": "wait_limit"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn job_wait_uses_read_wait_lane() {
        assert_eq!(Lane::for_tool("job_wait"), Lane::ReadWait);
        assert_eq!(Lane::for_tool("job_cancel"), Lane::Control);
        assert_eq!(Lane::for_tool("job_get"), Lane::Control);
    }

    #[tokio::test]
    async fn read_wait_limits_caller_to_two_while_control_and_read_stay_available() {
        let admission = Arc::new(Admission::default());
        let principal = Principal::DelegatedExecutor("default".into());
        let entered = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(3));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let adm = Arc::clone(&admission);
            let p = principal.clone();
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            handles.push(tokio::spawn(async move {
                adm.run(Lane::ReadWait, &p, move || {
                    entered.wait();
                    release.wait();
                    "waited"
                })
                .await
            }));
        }
        tokio::task::spawn_blocking(move || entered.wait()).await.unwrap();

        let third = admission
            .run(Lane::ReadWait, &principal, || "should_not_run")
            .await
            .unwrap_err();
        assert_eq!(third.code, ErrorCode::ResourceBusy);
        assert_eq!(third.details.as_ref().unwrap()["reason"], "wait_limit");
        assert_eq!(third.details.as_ref().unwrap()["retry_after_ms"], 500);

        let control = admission
            .run(Lane::Control, &principal, || "cancel_ok")
            .await
            .unwrap();
        assert_eq!(control.0, "cancel_ok");

        let read = admission
            .run(Lane::Read, &principal, || "read_ok")
            .await
            .unwrap();
        assert_eq!(read.0, "read_ok");

        tokio::task::spawn_blocking(move || release.wait()).await.unwrap();
        for handle in handles {
            assert_eq!(handle.await.unwrap().unwrap().0, "waited");
        }
    }

    #[tokio::test]
    async fn dropping_read_wait_future_cancels_sleep_and_frees_slot() {
        struct TempDirGuard(std::path::PathBuf);
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = TempDirGuard(
            std::env::temp_dir().join(format!("epb-admission-test-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir_all(&dir.0).unwrap();
        let store = bridge_core::state::StateStore::open(dir.0.join("state.sqlite3")).unwrap();
        let proj = store.register_project(&dir.0, "Wait cancel", "root_cancel").unwrap();
        let host = bridge_types::HostId::parse("host_test01").unwrap();
        let disp = bridge_adapters::mcp::McpDispatcher::new(
            store,
            bridge_adapters::mcp::McpAdapterConfig::new(Principal::Local, host),
        );
        let run = disp
            .dispatch_tool(
                "task_submit",
                &json!({
                    "project_id": proj.project_id,
                    "task_id": "t_cancel_wait",
                    "operation_id": "op_cancel_wait"
                }),
            )
            .unwrap();
        let run_id = run["run_id"].as_str().unwrap().to_owned();

        let admission = Arc::new(Admission::default());
        let principal = Principal::Local;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        let adm = Arc::clone(&admission);
        let pid = proj.project_id.clone();
        let task = tokio::spawn(async move {
            let _ = adm
                .run(Lane::ReadWait, &principal, move || {
                    let _ = started_tx.send(());
                    let res = disp.dispatch_tool(
                        "job_wait",
                        &json!({
                            "project_id": pid,
                            "job_ids": [run_id],
                            "timeout_seconds": 15,
                            "include_output": false
                        }),
                    );
                    let _ = done_tx.send(res);
                })
                .await;
        });
        started_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let dropped_at = Instant::now();
        task.abort();
        let _ = task.await;
        let err = tokio::time::timeout(Duration::from_secs(2), done_rx)
            .await
            .expect("job_wait must wake quickly when HTTP future is dropped")
            .unwrap()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TransientDisconnect);
        assert!(dropped_at.elapsed() < Duration::from_secs(2));

        let next = admission
            .run(Lane::ReadWait, &Principal::Local, || "slot_free")
            .await
            .unwrap();
        assert_eq!(next.0, "slot_free");
    }
}
