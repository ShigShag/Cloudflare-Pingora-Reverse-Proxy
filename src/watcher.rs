use async_trait::async_trait;
use log::{error, info, warn};
use pingora::services::background::BackgroundService;
use pingora_core::server::ShutdownWatch;
use std::fs::File;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::config::{AppConfig, RawConfig};
use crate::session_store::SESSION_STORE;

pub struct ConfigWatcher {
    pub path: String,
    pub config: Arc<RwLock<AppConfig>>,
    pub last_mtime: Arc<RwLock<SystemTime>>,
}

#[async_trait]
impl BackgroundService for ConfigWatcher {
    fn start<'life0, 'async_trait>(
        &'life0 self,
        mut shutdown: ShutdownWatch,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let path = Path::new(&self.path);
            let mut tick_counter: u32 = 0;

            loop {
                // 1. Perform the check and reload logic
                if path.exists() {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        if let Ok(mtime) = metadata.modified() {
                            let needs_reload = {
                                let last = self.last_mtime.read().unwrap_or_else(|e| {
                                    warn!("Last mtime lock poisoned, recovering");
                                    e.into_inner()
                                });
                                mtime > *last
                            };

                            if needs_reload {
                                info!("Config change detected, reloading...");
                                match File::open(path) {
                                    Ok(file) => match serde_yaml_ng::from_reader::<_, RawConfig>(file) {
                                        Ok(raw_config) => {
                                            let new_config = AppConfig::from_raw(raw_config);

                                            // Clear session bindings for hosts whose config changed
                                            {
                                                let old_conf = self.config.read().unwrap_or_else(|e| e.into_inner());
                                                for (hostname, new_upstream) in &new_config.hosts {
                                                    let old_binding = old_conf
                                                        .hosts
                                                        .get(hostname)
                                                        .and_then(|u| u.session_binding.as_ref());
                                                    let new_binding = new_upstream.session_binding.as_ref();
                                                    if old_binding != new_binding {
                                                        info!("Session binding config changed for {}, clearing bindings", hostname);
                                                        SESSION_STORE.clear_host(hostname);
                                                    }
                                                }
                                                // Clear bindings for hosts that were removed entirely
                                                for hostname in old_conf.hosts.keys() {
                                                    if !new_config.hosts.contains_key(hostname) {
                                                        SESSION_STORE.clear_host(hostname);
                                                    }
                                                }
                                            }

                                            *self.config.write().unwrap_or_else(|e| {
                                                warn!("Config lock poisoned, recovering");
                                                e.into_inner()
                                            }) = new_config;
                                            *self.last_mtime.write().unwrap_or_else(|e| {
                                                warn!("Last mtime lock poisoned, recovering");
                                                e.into_inner()
                                            }) = mtime;
                                            info!("Configuration reloaded.");
                                        }
                                        Err(e) => error!("Failed to parse config file: {e}"),
                                    },
                                    Err(e) => error!("Failed to open config file: {e}"),
                                }
                            }
                        }
                    }
                }

                // 2. Periodic session store cleanup (every 60s = 12 ticks * 5s)
                tick_counter += 1;
                if tick_counter % 12 == 0 {
                    SESSION_STORE.evict_expired();
                }

                // 3. Wait for either the interval OR the shutdown signal
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        // Continue loop
                    }
                    _ = shutdown.changed() => {
                        info!("Config watcher shutting down.");
                        break;
                    }
                }
            }
        })
    }
}
