#[cfg(test)]
pub(crate) mod stamp_handler_test_support {
    use slog::{Drain, Logger};

    pub fn create_test_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(slog::Level::Debug)
            .fuse();
        slog::Logger::root(drain, slog::o!("version" => "0.5"))
    }
}
