//! Closing a channel without cutting off its last messages (review 2 item
//! 13): a `PeerPairing{Rejected}` or an `Error` queued right before the
//! close must reach Remora, so the channel's I/O is cancelled only after
//! its writer has sent everything queued before the close, or after
//! [`FLUSH_WAIT`] when the writer is stuck (a client that stopped reading).
//! The wait runs on its own thread: the event loop never blocks on it.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// How long a closing channel's writer may take to send what was queued.
pub const FLUSH_WAIT: Duration = Duration::from_secs(2);

/// Waits until `writer_done` fires or disconnects (the writer sent
/// everything and ended, or failed), at most `wait`, then runs `cancel`.
/// Returns the waiting thread (None: no thread could start, and `cancel`
/// already ran).
pub fn close_after_flush(
    writer_done: Receiver<()>,
    wait: Duration,
    cancel: impl FnOnce() + Send + 'static,
) -> Option<JoinHandle<()>> {
    let cancel = Arc::new(Mutex::new(Some(cancel)));
    let c2 = cancel.clone();
    let run = move || {
        let _ = writer_done.recv_timeout(wait);
        if let Some(f) = c2.lock().unwrap_or_else(|p| p.into_inner()).take() {
            f();
        }
    };
    match std::thread::Builder::new()
        .name("close-flush".into())
        .spawn(run)
    {
        Ok(t) => Some(t),
        Err(_) => {
            if let Some(f) = cancel.lock().unwrap_or_else(|p| p.into_inner()).take() {
                f();
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A writer that takes a while per message: the cancel comes after the
    /// last queued message was written, not right after the close.
    #[test]
    fn queued_messages_are_written_before_the_cancel() {
        let (tx, rx) = mpsc::sync_channel::<u32>(8);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let l2 = log.clone();
        let writer = std::thread::spawn(move || {
            for m in rx {
                std::thread::sleep(Duration::from_millis(30));
                l2.lock().unwrap().push(format!("wrote {m}"));
            }
            drop(done_tx);
        });
        for m in 0..4 {
            tx.send(m).unwrap();
        }
        // The close: no more messages, then the flush wait and the cancel.
        drop(tx);
        let l3 = log.clone();
        let t = close_after_flush(done_rx, FLUSH_WAIT, move || {
            l3.lock().unwrap().push("cancel".into());
        })
        .unwrap();
        t.join().unwrap();
        writer.join().unwrap();
        let log = log.lock().unwrap();
        assert_eq!(*log, ["wrote 0", "wrote 1", "wrote 2", "wrote 3", "cancel"]);
    }

    /// A stuck writer does not hold the close up past the wait.
    #[test]
    fn a_stuck_writer_is_cancelled_after_the_wait() {
        let (_done_tx, done_rx) = mpsc::channel::<()>();
        let cancelled = Arc::new(Mutex::new(None));
        let c2 = cancelled.clone();
        let start = Instant::now();
        close_after_flush(done_rx, Duration::from_millis(100), move || {
            *c2.lock().unwrap() = Some(start.elapsed());
        })
        .unwrap()
        .join()
        .unwrap();
        let took = cancelled.lock().unwrap().unwrap();
        assert!(took >= Duration::from_millis(100) && took < Duration::from_secs(2));
    }
}
