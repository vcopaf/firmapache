use anyhow::{Context, Result};
use mini_firmador::{
    config::AppConfig,
    init_tracing,
    server::{self, AppState},
};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = AppConfig::load().context("could not load service configuration")?;
    server::serve(AppState::new(config)).await
}
