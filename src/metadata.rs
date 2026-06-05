pub const APP_NAME: &str = "FirMapache";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_DATE: &str = match option_env!("FIRMAPACHE_BUILD_DATE") {
    Some(value) => value,
    None => "unknown",
};
pub const GIT_COMMIT: &str = match option_env!("FIRMAPACHE_GIT_COMMIT") {
    Some(value) => value,
    None => "unknown",
};
pub const RELEASE_CHANNEL: &str = "stable";
pub const LICENSE: &str = "GPL-3.0";
pub const AUTHOR: &str = "Vladimir Copa Fabian";
pub const CONTACT_EMAIL: &str = "vcopafabian@gmail.com";
pub const REPOSITORY_URL: &str = "https://github.com/vcopaf/firmapache";
