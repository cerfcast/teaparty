use slog::Logger;
use rocket::State;
use crate::monitor::Monitor;

#[get("/sessions")]
fn index(monitor: &State<Monitor>) -> String {
    serde_json::to_string(&monitor.sessions).unwrap().to_string()
}

pub fn launch_meta(monitor: Monitor, logger: Logger) {
    {
        let logger = logger.clone();
        let joinable = std::thread::spawn(move || {
            slog::info!(logger, "Starting the meta thread!");
            let r = rocket::build()
                .configure(rocket::Config::release_default())
                .manage(monitor)
                .mount("/", routes![index])
                .launch();

            let rt = rocket::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Uh oh!");
            rt.block_on(r).expect("Could not start!");
        });
        joinable.join().unwrap();
    }
    slog::info!(logger, "Stopping the meta thread!");
}
