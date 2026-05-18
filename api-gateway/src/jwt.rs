//! JWT issuance and validation — RS256 asymmetric keys.
//!
//! The gateway holds the private key and signs tokens.
//! It validates tokens on every inbound request.
//!
//! In dev mode (no key files configured) we generate an ephemeral RSA key
//! pair at startup.  Set RSA_PRIVATE_KEY_PATH / RSA_PUBLIC_KEY_PATH env vars
//! to use persistent keys in production.

use std::sync::Arc;

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use tracing::info;

use shared::{errors::AppError, models::Claims};

const TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour
const ISSUER: &str = "securenet-gateway";

// ── JwtKeys ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct JwtKeys {
    encoding: Arc<EncodingKey>,
    decoding: Arc<DecodingKey>,
}

impl JwtKeys {
    /// Load RS256 keys from PEM files, or generate ephemeral keys in dev mode.
    pub fn load_or_generate() -> anyhow::Result<Self> {
        let priv_path = std::env::var("RSA_PRIVATE_KEY_PATH").ok();
        let pub_path  = std::env::var("RSA_PUBLIC_KEY_PATH").ok();

        match (priv_path, pub_path) {
            (Some(priv_p), Some(pub_p)) => {
                let priv_pem = std::fs::read(&priv_p)?;
                let pub_pem  = std::fs::read(&pub_p)?;
                info!(priv_path = %priv_p, "jwt.keys_loaded_from_file");
                Ok(Self {
                    encoding: Arc::new(EncodingKey::from_rsa_pem(&priv_pem)?),
                    decoding: Arc::new(DecodingKey::from_rsa_pem(&pub_pem)?),
                })
            }
            _ => {
                // Dev mode — generate ephemeral RSA-2048 key pair
                info!("jwt.generating_ephemeral_keys - set RSA_*_KEY_PATH for production");
                Self::generate_ephemeral()
            }
        }
    }

    fn generate_ephemeral() -> anyhow::Result<Self> {
        use rsa::{pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey, RsaPrivateKey};
        use rand::thread_rng;

        let mut rng     = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key  = private_key.to_public_key();

        let priv_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
            .to_string();
        let pub_pem  = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

        Ok(Self {
            encoding: Arc::new(EncodingKey::from_rsa_pem(priv_pem.as_bytes())?),
            decoding: Arc::new(DecodingKey::from_rsa_pem(pub_pem.as_bytes())?),
        })
    }

    /// Sign a JWT for the given username with the given roles.
    pub fn sign(&self, username: &str, roles: Vec<String>) -> Result<String, AppError> {
        let now    = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub:   username.to_string(),
            iat:   now,
            exp:   now + TOKEN_EXPIRY_SECS,
            iss:   ISSUER.to_string(),
            roles,
        };
        encode(&Header::new(Algorithm::RS256), &claims, &self.encoding)
            .map_err(|e| AppError::Internal(e.to_string()))
    }

    /// Validate a JWT and return its claims.
    pub fn validate(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[ISSUER]);
        decode::<Claims>(token, &self.decoding, &validation)
            .map(|d| d.claims)
            .map_err(|e| AppError::AuthInvalidToken(e.to_string()))
    }
}

// ── User store (in-memory for demo) ──────────────────────────────────────────

#[derive(Clone)]
pub struct UserStore {
    /// username → bcrypt hash
    users: std::collections::HashMap<String, (String, Vec<String>)>,
}

impl UserStore {
    pub fn seeded() -> Self {
        let mut users = std::collections::HashMap::new();
        // bcrypt hash of "hunter2"
        let hash = bcrypt::hash("hunter2", bcrypt::DEFAULT_COST).unwrap();
        users.insert("alice".into(), (hash.clone(), vec!["user".into()]));
        users.insert("admin".into(), (
            bcrypt::hash("admin123", bcrypt::DEFAULT_COST).unwrap(),
            vec!["user".into(), "admin".into()],
        ));
        Self { users }
    }

    /// Verify credentials and return roles on success.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<Vec<String>> {
        let (hash, roles) = self.users.get(username)?;
        if bcrypt::verify(password, hash).unwrap_or(false) {
            Some(roles.clone())
        } else {
            None
        }
    }
}
