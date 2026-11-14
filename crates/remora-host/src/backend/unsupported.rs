//! Platforms without a capture and input backend yet (Linux, macOS). The
//! host still builds there and runs with `--demo`; the real backends are
//! on the roadmap (docs/HOST.md).

use std::io;

use super::Backend;

/// The platform's name for the error message.
fn platform() -> &'static str {
    if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "this platform"
    }
}

/// Always an error: no screen capture or input injection here yet.
pub fn backend() -> io::Result<Backend> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "screen capture and input are not supported on {} yet; run with --demo for the test pattern",
            platform()
        ),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn says_what_is_missing() {
        let Err(e) = super::backend() else {
            panic!("no backend expected")
        };
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("--demo"), "{e}");
    }
}
