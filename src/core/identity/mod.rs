pub mod identity;
pub mod manager;

pub use identity::{ResolvedSigningIdentity, SigningIdentity};
pub use manager::{IdentityError, build_signing_identities, resolve_signing_identity};
