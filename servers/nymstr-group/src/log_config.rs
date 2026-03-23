use chrono::Local;
use fern::{
    colors::{Color, ColoredLevelConfig},
    Dispatch,
};
use log::LevelFilter;
use std::io;

/// Initialize logging to file and stdout with timestamps and colored levels.
/// When `stdio_mode` is true, logs go only to the file (stdout is reserved for protocol messages).
pub fn init_logging(log_file: &str, stdio_mode: bool) -> anyhow::Result<()> {
    // configure colors for terminal output
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Cyan)
        .trace(Color::BrightBlack);

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
        .level(LevelFilter::Info)
        .chain(fern::log_file(log_file)?);

    if !stdio_mode {
        dispatch = dispatch.chain(io::stdout());
    }

    dispatch.apply()?;
    Ok(())
}
