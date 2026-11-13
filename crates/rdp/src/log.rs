use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enables protocol tracing to stderr.
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {
        if $crate::log::verbose() {
            eprintln!("[rdp] {}", format!($($t)*));
        }
    };
}
