pub mod keygen;
pub mod open;
pub mod receipt;
pub mod recipient;
pub mod seal;
pub mod trust;
pub mod verify;

use sealdrop_core::progress::{Progress, ProgressEvent};

/// Progress goes to stderr so stdout stays clean for the values scripts parse.
pub struct StderrProgress;

impl Progress for StderrProgress {
    fn on(&self, e: ProgressEvent) {
        match e {
            ProgressEvent::Packing { path } => eprintln!("packing {path}"),
            ProgressEvent::Encrypted { bytes } => eprintln!("encrypted {bytes} bytes"),
            ProgressEvent::Contacting { service } => {
                eprintln!("contacting release service {service}")
            }
            ProgressEvent::Verifying => eprintln!("verifying manifest"),
            ProgressEvent::Extracting { path } => eprintln!("extracting to {path}"),
            ProgressEvent::Done => {}
        }
    }
}

/// Parses `90s`, `10m`, `6h`, `3d` into seconds.
pub fn parse_window(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let bad = || {
        anyhow::anyhow!(
            "invalid window `{s}`; use a whole number and s, m, h or d, e.g. 90s, 10m, 6h, 3d"
        )
    };
    let (num, mult) = [("s", 1u64), ("m", 60), ("h", 3600), ("d", 86_400)]
        .iter()
        .find_map(|(suffix, mult)| s.strip_suffix(suffix).map(|n| (n, *mult)))
        .ok_or_else(bad)?;
    let n: u64 = num.parse().map_err(|_| bad())?;
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("window too large"))?;
    anyhow::ensure!(secs >= 1, "window must be at least 1 second");
    Ok(secs)
}

/// Formats a window in the largest whole unit: `600` -> `10m`.
pub fn human(secs: u64) -> String {
    // `is_multiple_of` is newer than the workspace MSRV (1.85), so divide and multiply back.
    for (unit, suffix) in [(86_400u64, "d"), (3600, "h"), (60, "m")] {
        if secs >= unit && secs / unit * unit == secs {
            return format!("{}{suffix}", secs / unit);
        }
    }
    format!("{secs}s")
}

/// The release-service deposit token: environment first, then the key-store settings.
pub fn release_token(settings: &sealdrop_core::keys::Settings) -> anyhow::Result<String> {
    std::env::var("SEALDROP_RELEASE_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| settings.release_token.clone())
        .ok_or_else(|| anyhow::anyhow!("set SEALDROP_RELEASE_TOKEN or settings.release_token"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn windows() {
        assert_eq!(super::parse_window("90s").unwrap(), 90);
        assert_eq!(super::parse_window("10m").unwrap(), 600);
        assert_eq!(super::parse_window("6h").unwrap(), 21600);
        assert_eq!(super::parse_window("3d").unwrap(), 259_200);
        assert!(super::parse_window("10").is_err());
        assert!(super::parse_window("0m").is_err());
        // Non-ASCII input must be an error, never a panic.
        for bad in [
            "",
            "m",
            "10é",
            "é",
            "１０m",
            "10\u{1F600}",
            "-5m",
            "1.5h",
            "99999999999999999999d",
        ] {
            assert!(super::parse_window(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn human_windows() {
        assert_eq!(super::human(600), "10m");
        assert_eq!(super::human(1), "1s");
        assert_eq!(super::human(90), "90s");
        assert_eq!(super::human(21600), "6h");
        assert_eq!(super::human(259_200), "3d");
    }
}
