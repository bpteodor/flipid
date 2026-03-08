use std::collections::HashMap;

use crate::core::config::SecretConfig;

pub struct Secret {
    pub scope: String,
    pub key: jwt::EncodingKey,
    pub raw: Vec<u8>,
}

pub struct Secrets(HashMap<String, Secret>);

impl Secrets {
    pub fn load(configs: &[SecretConfig]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut map = HashMap::new();
        for cfg in configs {
            let (raw, key) = match cfg.scope.as_str() {
                "HS256" | "HS512" => {
                    let bytes = cfg
                        .value
                        .as_ref()
                        .ok_or_else(|| format!("secret '{}': HS256/HS512 requires 'value'", cfg.name))?
                        .as_bytes()
                        .to_vec();
                    let key = jwt::EncodingKey::from_secret(&bytes);
                    (bytes, key)
                }
                "RS256" | "RS512" => {
                    let path = cfg
                        .file
                        .as_ref()
                        .ok_or_else(|| format!("secret '{}': RS256/RS512 requires 'file'", cfg.name))?;
                    let bytes = std::fs::read(path)?;
                    let key = jwt::EncodingKey::from_rsa_pem(&bytes)?;
                    (bytes, key)
                }
                "ES256" | "ES384" | "ES512" => {
                    let path = cfg
                        .file
                        .as_ref()
                        .ok_or_else(|| format!("secret '{}': ES256/384/512 requires 'file'", cfg.name))?;
                    let bytes = std::fs::read(path)?;
                    let key = jwt::EncodingKey::from_ec_pem(&bytes)?;
                    (bytes, key)
                }
                scope => return Err(format!("secret '{}': unknown scope '{}'", cfg.name, scope).into()),
            };
            map.insert(
                cfg.name.clone(),
                Secret {
                    scope: cfg.scope.clone(),
                    key,
                    raw,
                },
            );

            log::info!("[{:?}] loaded {:?} key from {:?}", cfg.name.clone(), cfg.scope.clone(), cfg.file.clone())
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
