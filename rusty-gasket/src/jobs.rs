//! Background job and scheduler support.
//!
//! The public API is closure-based so generated services can register jobs with
//! ordinary async blocks. The framework owns the boxed future and task-handle
//! plumbing internally.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::plugin::{Plugin, PluginOrdering, PrepareContext, ShutdownContext};
use crate::{BoxError, BoxFuture};

type JobTask = Arc<dyn Fn() -> BoxFuture<'static, Result<(), BoxError>> + Send + Sync>;

#[derive(Clone)]
struct ScheduledJob {
    name: &'static str,
    interval: Duration,
    task: JobTask,
}

impl std::fmt::Debug for ScheduledJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScheduledJob")
            .field("name", &self.name)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// Plugin that runs recurring background jobs.
///
/// Jobs start during the `prepare` phase and are aborted during shutdown.
/// Register jobs with [`Self::every`] so application code can use normal async
/// closures without seeing Tower or boxed-future internals.
#[derive(Debug, Clone, Default)]
pub struct SchedulerPlugin {
    jobs: Vec<ScheduledJob>,
    handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl SchedulerPlugin {
    /// Create an empty scheduler plugin.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a recurring job.
    ///
    /// The job runs after each interval tick. If a run returns an error, the
    /// error is logged and the next tick still runs.
    #[must_use]
    pub fn every<Job, JobFuture>(mut self, name: &'static str, interval: Duration, job: Job) -> Self
    where
        Job: Fn() -> JobFuture + Send + Sync + 'static,
        JobFuture: Future<Output = Result<(), BoxError>> + Send + 'static,
    {
        let task = Arc::new(move || {
            let future = job();
            let boxed: BoxFuture<'static, Result<(), BoxError>> = Box::pin(future);
            boxed
        });
        self.jobs.push(ScheduledJob {
            name,
            interval,
            task,
        });
        self
    }
}

impl Plugin for SchedulerPlugin {
    fn name(&self) -> &'static str {
        "gasket:scheduler"
    }

    fn ordering(&self) -> PluginOrdering {
        PluginOrdering::new().before(["gasket:server"])
    }

    async fn prepare(&self, _context: &mut PrepareContext) -> Result<(), BoxError> {
        let mut new_handles = Vec::with_capacity(self.jobs.len());
        for job in &self.jobs {
            let name = job.name;
            let interval = job.interval;
            let task = Arc::clone(&job.task);
            new_handles.push(tokio::spawn(run_job_loop(name, interval, task)));
        }

        match self.handles.lock() {
            Ok(mut handles) => handles.extend(new_handles),
            Err(error) => {
                for handle in new_handles {
                    handle.abort();
                }
                return Err(format!("scheduler handle store is unavailable: {error}").into());
            }
        }

        Ok(())
    }

    async fn shutdown(&self, _context: &ShutdownContext) -> Result<(), BoxError> {
        let handles = match self.handles.lock() {
            Ok(mut handles) => handles.drain(..).collect::<Vec<_>>(),
            Err(error) => {
                tracing::warn!(error = %error, "Scheduler handle store was poisoned during shutdown");
                Vec::new()
            }
        };

        for handle in handles {
            handle.abort();
        }

        Ok(())
    }
}

async fn run_job_loop(name: &'static str, interval: Duration, task: JobTask) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(error) = task().await {
            tracing::warn!(job = name, error = %error, "Scheduled job failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::config::AppConfigDefinition;

    #[tokio::test(start_paused = true)]
    async fn scheduler_runs_registered_job_on_interval() {
        let runs = Arc::new(AtomicUsize::new(0));
        let observed_runs = Arc::clone(&runs);
        let plugin =
            SchedulerPlugin::new().every("test:tick", Duration::from_secs(10), move || {
                let observed_runs = Arc::clone(&observed_runs);
                async move {
                    observed_runs.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            });

        let config = AppConfigDefinition::new("test")
            .resolve()
            .expect("resolve config");
        let mut context = PrepareContext::new(config, http::Extensions::new());
        plugin
            .prepare(&mut context)
            .await
            .expect("scheduler prepare");

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;

        assert_eq!(runs.load(Ordering::SeqCst), 1);

        plugin
            .shutdown(&ShutdownContext::new(http::Extensions::new()))
            .await
            .expect("scheduler shutdown");
    }
}
