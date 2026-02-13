use async_trait::async_trait;
use log::{error, info, warn};
use pingora::services::background::BackgroundService;
use pingora_core::server::ShutdownWatch;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::{AppConfig, RawConfig};
use crate::session_store::SESSION_STORE;

/// Compute an xxh3 hash of a file's contents. Returns `None` on any I/O error.
pub fn compute_file_hash(path: &Path) -> Option<u64> {
    fs::read(path).ok().map(|buf| xxhash_rust::xxh3::xxh3_64(&buf))
}

pub struct ConfigWatcher {
    pub path: String,
    pub config: Arc<RwLock<AppConfig>>,
    pub last_hash: Arc<RwLock<u64>>,
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
            loop {
                // 1. Compute hash of current file and compare
                if let Some(new_hash) = compute_file_hash(path) {
                    let needs_reload = {
                        let last = self.last_hash.read().unwrap_or_else(|e| {
                            warn!("Last hash lock poisoned, recovering");
                            e.into_inner()
                        });
                        new_hash != *last
                    };

                    if needs_reload {
                        info!("Config change detected, reloading...");
                        match fs::read_to_string(path) {
                            Ok(contents) => match serde_yaml_ng::from_str::<RawConfig>(&contents) {
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

                                        // Log if default_host session binding changed
                                        let old_default_binding = old_conf
                                            .default_upstream
                                            .as_ref()
                                            .and_then(|u| u.session_binding.as_ref());
                                        let new_default_binding = new_config
                                            .default_upstream
                                            .as_ref()
                                            .and_then(|u| u.session_binding.as_ref());
                                        if old_default_binding != new_default_binding {
                                            if old_default_binding.is_some() {
                                                info!("default_host session binding config changed; existing sessions will re-bind on expiry");
                                            }
                                        }
                                    }

                                    *self.config.write().unwrap_or_else(|e| {
                                        warn!("Config lock poisoned, recovering");
                                        e.into_inner()
                                    }) = new_config;
                                    *self.last_hash.write().unwrap_or_else(|e| {
                                        warn!("Last hash lock poisoned, recovering");
                                        e.into_inner()
                                    }) = new_hash;
                                    info!("Configuration reloaded.");
                                }
                                Err(e) => error!("Failed to parse config file: {e}"),
                            },
                            Err(e) => error!("Failed to read config file: {e}"),
                        }
                    }
                }

                // 2. Wait for either the interval OR the shutdown signal
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
