use crate::core::config::SecretConfig;
use bcrypt::verify as bcrypt_verify;
use jwt::EncodingKey;
use std::collections::HashMap;

pub struct Secret {
    pub kind: String,
    pub key: EncodingKey, // todo lazy load & cache
    pub raw: Vec<u8>,
}

pub struct Secrets(HashMap<String, Secret>);

impl Secrets {
    pub fn load(configs: &[SecretConfig]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut map = HashMap::new();
        for cfg in configs {
            let raw = if cfg.value.is_some() {
                cfg.value
                    .as_ref()
                    .ok_or_else(|| format!("secret '{}': HS256/HS512 requires 'value'", cfg.name))?
                    .as_bytes()
                    .to_vec()
            } else if cfg.file.is_some() {
                let path = cfg
                    .file
                    .as_ref()
                    .ok_or_else(|| format!("secret '{}': RS256/RS512 requires 'file'", cfg.name))?;
                std::fs::read(path)?
            } else {
                error!("failed to load secret {} of type {}", cfg.name, cfg.kind);
                continue;
            };

            let key = match cfg.kind.as_str() {
                "SECRET" => EncodingKey::from_secret(&raw),

                "RSA" => EncodingKey::from_rsa_pem(&raw).map_err(|_| format!("invalid RSA key:{}", cfg.name))?,

                "EC" => EncodingKey::from_ec_pem(&raw).map_err(|_| format!("invalid EC key:{}", cfg.name))?,

                "ED" => EncodingKey::from_ed_pem(&raw).map_err(|_| format!("invalid ED key:{}", cfg.name))?,

                kind => return Err(format!("secret '{}': unknown type '{}'", cfg.name, kind).into()),
            };
            map.insert(
                cfg.name.clone(),
                Secret {
                    kind: cfg.kind.clone(),
                    key,
                    raw,
                },
            );

            log::info!(
                "loaded secret [{:?}] of type {:?} from {:?}",
                cfg.name.clone(),
                cfg.kind.clone(),
                cfg.file.clone()
            )
        }
        Ok(Secrets(map))
    }

    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.0.get(name)
    }

    pub fn values(&self) -> impl Iterator<Item = (&String, &Secret)> {
        self.0.iter()
    }
}

pub fn verify_password(expected_password: &str, received_password: &str) -> actix_web::Result<(), String> {
    if received_password.len() == 0 {
        Err("no password received")?
    }

    if expected_password.starts_with("{BCRYPT}") {
        let valid = bcrypt_verify(received_password, &expected_password[8..]).map_err(|e| format!("bcrypt error: {}", e))?;
        if !valid {
            Err("invalid password".to_string())
        } else {
            Ok(())
        }
    } else {
        Err("invalid password encoding".to_string())
    }
}
