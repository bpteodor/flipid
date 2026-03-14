use std::collections::HashMap;

use crate::core::config::SecretConfig;

pub struct Secret {
    pub kind: String,
    pub key: jwt::EncodingKey, // todo lazy load & cache
    pub raw: Vec<u8>,
}

pub struct Secrets(HashMap<String, Secret>);

impl Secrets {
    pub fn load(configs: &[SecretConfig]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut map = HashMap::new();
        for cfg in configs {

            let bytes = if cfg.value.is_some() {
                cfg.value.as_ref().ok_or_else(|| format!("secret '{}': HS256/HS512 requires 'value'", cfg.name))?.as_bytes().to_vec()
            } else if cfg.file.is_some() {
                let path = cfg.file.as_ref().ok_or_else(|| format!("secret '{}': RS256/RS512 requires 'file'", cfg.name))?;
                std::fs::read(path)?
            } else {
                error!("failed to load secret {} of type {}", cfg.name, cfg.kind);
                continue;
            };

            let (raw, key) = match cfg.kind.as_str() {
                "SECRET" => {
                    let key = jwt::EncodingKey::from_secret(&bytes);
                    (bytes, key)
                }
                "RSA" => {
                    let key = jwt::EncodingKey::from_rsa_pem(&bytes)?;
                    (bytes, key)
                }
                "EC" => {
                    let key = jwt::EncodingKey::from_ec_pem(&bytes)?;
                    (bytes, key)
                }
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

            log::info!("loaded secret [{:?}] of type {:?} from {:?}", cfg.name.clone(), cfg.kind.clone(), cfg.file.clone())
        }
        Ok(Secrets(map))
    }

    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.0.get(name)
    }

    pub fn values(&self) -> impl Iterator<Item=(&String, &Secret)> {
        self.0.iter()
    }
}
