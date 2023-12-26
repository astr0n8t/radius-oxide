#[macro_use]
extern crate log;

use std::process;
use tokio::signal;
use radius::server::Server;


#[tokio::main]
async fn main() {
    env_logger::init();

    let settings = radius_oxide::settings::OxideSettings::new().unwrap_or_else(|e|{
        info!("{:?}", e);
        process::exit(1);
    });
    
    let secret_handler = radius_oxide::OxideSecretProvider::new(settings.get_secret());
    let request_handler = radius_oxide::OxideRequestHandler::new(settings);

    // start UDP listening
    let mut server = Server::listen("0.0.0.0", 1812, request_handler, secret_handler)
        .await
        .unwrap();
    server.set_buffer_size(1500); // default value: 1500
    server.set_skip_authenticity_validation(false); // default value: false

    // once it has reached here, a RADIUS server is now ready
    info!(
        "server is now ready: {}",
        server.get_listen_address().unwrap()
    );

    // start the loop to handle the RADIUS requests
    let result = server.run(signal::ctrl_c()).await;
    info!("{:?}", result);
    if result.is_err() {
        process::exit(1);
    }
}

