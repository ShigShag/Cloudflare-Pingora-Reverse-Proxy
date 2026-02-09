mod config;
mod proxy;
mod session_store;
mod watcher;

use config::{AppConfig, ProxyConfig, RawConfig};
use env_logger::Env;
use log::info;
use pingora::prelude::*;
use pingora::services::background::background_service;
use pingora_core::listeners::tls::TlsSettings;
use proxy::HostSwitchProxy;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use watcher::ConfigWatcher;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // 1. Load Env Vars
    let env_conf = ProxyConfig::from_env();

    // 2. Initial Config Load
    info!("Loading config from: {}", env_conf.config_path);
    let config_file = File::open(&env_conf.config_path).expect("Could not open config file");
    let raw_config: RawConfig =
        serde_yaml_ng::from_reader(config_file).expect("Could not parse config file");
    let initial_config = AppConfig::from_raw(raw_config);

    // Create the shared state
    let config_wrapper = Arc::new(RwLock::new(initial_config));

    // 3. Initialize Pingora Server
    let mut my_server = Server::new(None).expect("Failed to create server");
    my_server.bootstrap();

    // 4. Setup Background Config Watcher
    let watcher_logic = ConfigWatcher {
        path: env_conf.config_path.clone(),
        config: config_wrapper.clone(),
        last_mtime: Arc::new(RwLock::new(SystemTime::now())),
    };

    let watcher_service = background_service("config_watcher", watcher_logic);
    my_server.add_service(watcher_service);

    // 5. Create Proxy Service
    let proxy_logic = HostSwitchProxy {
        config: config_wrapper,
    };
    let mut lb_service = http_proxy_service(&my_server.configuration, proxy_logic);

    // 6. Configure TLS
    let cert_path = format!("{}/server.crt", env_conf.cert_dir);
    let key_path = format!("{}/server.key", env_conf.cert_dir);

    if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
        panic!(
            "TLS Certificates not found at: {} and {}",
            cert_path, key_path
        );
    }

    let mut tls_settings = TlsSettings::intermediate(&cert_path, &key_path)
        .expect("Failed to load TLS certificates");
    tls_settings.enable_h2();

    info!("Listening on {} with TLS enabled", env_conf.address());
    lb_service.add_tls_with_settings(&env_conf.address(), None, tls_settings);

    // 7. Add Services to Server and Run
    my_server.add_service(lb_service);
    my_server.run_forever();
}
