use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    bind_address: SocketAddr,
    pub allowed_origins: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from(([127, 0, 0, 1], 4856)),
            allowed_origins: vec![
                "http://localhost:3000".to_owned(),
                "http://127.0.0.1:3000".to_owned(),
            ],
        }
    }
}

impl AppConfig {
    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }
}
