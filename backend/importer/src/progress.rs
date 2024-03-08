use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use std::io::IsTerminal;
use walker_common::progress::Progress;

/// Set up the env_logger and attach a progress interface if we are running on a terminal.
pub(crate) fn init_log_and_progress() -> Progress {
    let mut builder = env_logger::builder();
    let logger = builder.build();

    match std::io::stdin().is_terminal() {
        true => {
            let max_level = logger.filter();
            let multi = MultiProgress::new();

            let log = LogWrapper::new(multi.clone(), logger);
            // NOTE: LogWrapper::try_init is buggy and messes up the log levels
            log::set_boxed_logger(Box::new(log)).unwrap();
            log::set_max_level(max_level);

            multi.into()
        }
        false => Progress::default(),
    }
}
