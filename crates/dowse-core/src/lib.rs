pub mod inspector;
pub mod proxy;
pub mod recorder;
pub mod resolve;
pub mod score;
pub mod trim;

pub use inspector::PrefetchInspector;
pub use proxy::detect_proxy;
pub use recorder::RecordingInspector;
pub use resolve::{resolve_slot, ResolutionContext};
pub use score::score_hints;
