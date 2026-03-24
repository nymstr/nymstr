//! Logging initialization with fern.
//!
//! Supports colored terminal output, file logging, RUST_LOG env var,
//! and stdio_mode to suppress stdout (for JSON pipe testing).

use chrono::Local;
use fern::colors::{Color, ColoredLevelConfig};
use fern::Dispatch;
use log::LevelFilter;
use std::io;

/// Initialize logging to file and optionally stdout.
///
/// When `stdio_mode` is true, logs go only to the file
/// (stdout is reserved for protocol messages).
pub fn init_logging(log_file: &str, stdio_mode: bool) -> anyhow::Result<()> {
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Cyan)
        .trace(Color::BrightBlack);

    let log_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| match level.to_lowercase().as_str() {
            "trace" => Some(LevelFilter::Trace),
            "debug" => Some(LevelFilter::Debug),
            "info" => Some(LevelFilter::Info),
            "warn" => Some(LevelFilter::Warn),
            "error" => Some(LevelFilter::Error),
            _ => None,
        })
        .unwrap_or(LevelFilter::Info);

    let mut dispatch = Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().to_rfc3339(),
                colors.color(record.level()),
                record.target(),
                message
            ))
        })
        .level(log_level)
        .chain(fern::log_file(log_file)?);

    if !stdio_mode {
        dispatch = dispatch.chain(io::stdout());
    }

    dispatch.apply()?;
    Ok(())
}
