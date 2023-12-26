use std::collections::HashMap;
use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;
use sha2::{Sha512, Digest};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct OxideSettings {
    users: HashMap<String,AuthenticationEntry>,
    servers: Vec<IpAddr>,
    secret: String,
}

#[derive(Debug, Deserialize)]
struct DeserializedSettings {
    secret: String,
    #[serde(default)]
    servers: Vec<String>,
    #[serde(default)]
    users: Vec<DeserializedUsers>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
struct DeserializedUsers {
    #[serde(default)]
    username: String,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    mac_address: String,
    #[serde(default)]
    vlan_id: u16
}

impl OxideSettings {
    pub fn new() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::with_name("config").required(false))
            .add_source(File::with_name("/etc/radius-oxide/config").required(false))
            .add_source(Environment::with_prefix("RADIUS_OXIDE"))
            .build()?;

        let mut deserialized_settings: DeserializedSettings = s.try_deserialize().unwrap();

        let users: HashMap<String, AuthenticationEntry> = HashMap::new();

        let mut settings = Self {
            users,
            secret: deserialized_settings.secret,
            servers: vec![],
        };

        while deserialized_settings.servers.len() > 0 {
            let server_ip = match (&deserialized_settings.servers.pop().unwrap()).parse() {
                Ok(ip) => ip,
                Err(e) => return Err(ConfigError::Message(
                        format!("Unable to parse IP address {:?}", e)
                )),
            };
            settings.servers.push(server_ip);
        }

        while deserialized_settings.users.len() > 0 {
            let (key,entry) = match AuthenticationEntry::from_config(
                deserialized_settings.users.pop().unwrap()
            ) {
                Ok((key,entry)) => (key,entry),
                Err(e) => return Err(e),
            };
            settings.users.insert(key,entry);

        }

        debug!("Loaded config: {:?}", &settings);

        Ok(settings)
    }
    pub fn get_secret(&self) -> &str {
        &self.secret
    }
    // Returns if the user is authenticated and their respective vlan id
    pub fn authenticate(&self, user: &str, pass: &str) -> (bool, u16) {
        let user = String::from(user);
        let pass = String::from(pass);
        if self.users.contains_key(&user) {
            let user = self.users.get(&user).unwrap();
            if user.authenticate(pass) {
                return (true, user.get_vlan());
            }
        } 
        return (false, 0);
    }
    pub fn valid_server(&self, server: SocketAddr) -> bool {
        let ip = server.ip();
        if self.servers.contains(&ip) {
            return true;
        }
        false
    }

}

#[derive(Debug)]
enum AuthKinds {
    User,
    Mac,
}

#[derive(Debug)]
struct AuthenticationEntry {
    kind: AuthKinds,
    password: String,
    vlan: u16,
}

impl AuthenticationEntry {
    fn from_config(config: DeserializedUsers) -> Result<(String, Self), ConfigError> {
        let mut entry: AuthenticationEntry = Self {
            kind: AuthKinds::Mac,
            password: String::from(""),
            vlan: 0,
        };
        let key: String;
        if config.mac_address == "" {
            if config.username == "" || config.hash == "" {
                return Err(ConfigError::NotFound(
                    format!("No username, user hash, or mac_address for entry {:?}", 
                    config)
                ));
            }
            entry.kind = AuthKinds::User;
            entry.password = config.hash;
            key = config.username;
        } else {
            entry.password = config.mac_address.clone();
            key = config.mac_address;
        }

        if config.vlan_id == 0 {
            entry.vlan = 1;
            info!("VLAN not defined for entry: {:?} setting to VLAN 1", entry);
        } else {
            if config.vlan_id > 4096 {
                return Err(ConfigError::Message(
                    format!("Invalid VLAN id {:?} for entry {:?}", 
                    config.vlan_id, entry)
                ));
            }
            entry.vlan = config.vlan_id;
        }

        Ok((key,entry))
    }
    fn get_vlan(&self) -> u16 {
        self.vlan
    }
    fn authenticate(&self, password: String) -> bool {
        match self.kind {
            AuthKinds::User => self.authenticate_user(password),
            AuthKinds::Mac => self.authenticate_mac(password),
        }
    }
    fn authenticate_mac(&self, mac: String) -> bool {
        if self.password == mac {
            return true;
        }
        false
    }
    fn authenticate_user(&self, password: String) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(password.into_bytes());
        let result = hasher.finalize();
        let valid = match hex::decode(self.password.clone()) {
            Ok(v) => v,
            Err(e) => {
                info!("Could not decode hash from config into hex bytes: {:?}", e);
                return false;
            },
        };

        if result[..] == valid {
            return true;
        }
        false
    }
}

