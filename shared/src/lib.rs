//! # shared
//!
//! Common types, utilities, and middleware used by all SecureNet services.
//!
//! ## Module layout
//!
//! | Module          | Responsibility                                              |
//! |-----------------|-------------------------------------------------------------|
//! | `models`        | Wire types — `User`, `Order`, `CertBundle`, `Claims`, etc. |
//! | `errors`        | `AppError` unified error type with `IntoResponse` impl      |
//! | `tls`           | rustls `ServerConfig` / `ClientConfig` builders             |
//! | `rotation`      | `RotatingTlsConfig` — atomic cert swap, background task     |
//! | `identity`      | `ServiceIdentity` — sealed → unsealed boot state machine    |
//! | `attestation`   | TPM2 quote generation; Secure Boot state check              |
//! | `telemetry`     | OpenTelemetry init, W3C `traceparent` extract/inject        |
//! | `chaos`         | Tower middleware — random delay/drop (feature = "chaos")    |

pub mod attestation;
pub mod chaos;
pub mod errors;
pub mod identity;
pub mod models;
pub mod rotation;
pub mod telemetry;
pub mod tls;

// Convenient re-exports used across every service binary
pub use errors::AppError;
pub use models::{CertBundle, Claims, UnsealRequest, UnsealResponse};
