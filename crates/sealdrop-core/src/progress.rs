//! Progress reporting seam shared by CLI and desktop.

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Packing { path: String },
    Encrypted { bytes: u64 },
    Contacting { service: String },
    Verifying,
    Extracting { path: String },
    Done,
}

pub trait Progress {
    fn on(&self, event: ProgressEvent);
}

pub struct NoProgress;

impl Progress for NoProgress {
    fn on(&self, _: ProgressEvent) {}
}
