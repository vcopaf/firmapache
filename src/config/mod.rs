use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    bind_address: SocketAddr,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from(([127, 0, 0, 1], 4856)),
        }
    }
}

impl AppConfig {
    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }
}
