use std::collections::HashMap;
use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;
use sha2::{Sha512, Digest};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct OxideSettings {
    listen_address: String,
    listen_port: u16,
    users: HashMap<String,AuthenticationEntry>,
    servers: HashMap<IpAddr,AuthenticationServerEntry>,
    secret: String,
}

#[derive(Debug, Deserialize)]
struct DeserializedSettings {
    #[serde(default)]
    listen_address: String,
    #[serde(default)]
    listen_port: u16,
    secret: String,
    #[serde(default)]
    servers: Vec<DeserializedServers>,
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
    vlan_enabled: bool,
    #[serde(default)]
    vlan_id: u16
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
struct DeserializedServers {
    ip: String,
    #[serde(default)]
    default_vlan_enabled: bool,
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

        let mut deserialized_settings: DeserializedSettings = match s.try_deserialize() {
            Ok(settings) => settings,
            Err(e) => return Err(e),
        };

        if deserialized_settings.listen_address.len() == 0 {
            deserialized_settings.listen_address = String::from("0.0.0.0");
        } else {
            deserialized_settings.listen_address = match (&deserialized_settings.listen_address).parse() {
                Ok(a) => a,
                Err(e) => {
                    warn!("Unable to parse provided listen IP address {:?} 
                          will fall back to default",  e);
                    String::from("0.0.0.0")
                },
            };
        }

        if deserialized_settings.listen_port == 0 {
            deserialized_settings.listen_port = 1812;
        } 

        let mut settings = Self {
            listen_address: deserialized_settings.listen_address,
            listen_port: deserialized_settings.listen_port,
            users: HashMap::new(),
            secret: deserialized_settings.secret,
            servers: HashMap::new(),
        };

        while deserialized_settings.servers.len() > 0 {
            let mut server_entry = deserialized_settings.servers.pop().unwrap();

            let server_ip = match (&server_entry.ip).parse() {
                Ok(ip) => ip,
                Err(e) => return Err(ConfigError::Message(
                        format!("Unable to parse IP address {:?}", e)
                )),
            };

            if server_entry.vlan_id == 0 || server_entry.vlan_id > 4094 {
                server_entry.default_vlan_enabled = false;
                warn!("Invalid default VLAN ID for server entry {:?}, 
                      continuing but default vlan will be disabled", server_entry);
            }

            let server_entry = AuthenticationServerEntry{
                default_vlan_enabled: server_entry.default_vlan_enabled,
                vlan: server_entry.vlan_id,
            };
            settings.servers.insert(server_ip, server_entry);
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
    pub fn get_listen_address(&self) -> String {
        self.listen_address.clone()
    }
    pub fn get_listen_port(&self) -> u16 {
        self.listen_port
    }
    // Returns if the user is authenticated and their respective vlan id
    pub fn authenticate(&self, user: &str, pass: &str) -> (bool, Option<u16>) {
        let user = String::from(user);
        let pass = String::from(pass);
        if self.users.contains_key(&user) {
            let user = self.users.get(&user).unwrap();
            if user.authenticate(pass) {
                return (true, user.get_vlan());
            }
        } 
        return (false, None);
    }
    pub fn valid_server(&self, server: SocketAddr) -> bool {
        let ip = server.ip();
        if self.servers.contains_key(&ip) {
            return true;
        }
        false
    }
    pub fn get_server_default_vlan(&self, server: SocketAddr) -> Option<u16> {
        let ip = server.ip();
        let entry = match self.servers.get(&ip) {
            Some(entry) => entry,
            None => {
                warn!("Unable to find server entry which should exist for server {:?}", server);
                return None
            },
        };

        if entry.default_vlan_enabled {
            return Some(entry.vlan);
        }
        None
    }

}

#[derive(Debug)]
struct AuthenticationServerEntry {
    default_vlan_enabled: bool,
    vlan: u16,
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
    vlan_enabled: bool,
    vlan: u16,
}

impl AuthenticationEntry {
    fn from_config(config: DeserializedUsers) -> Result<(String, Self), ConfigError> {
        let mut entry: AuthenticationEntry = Self {
            kind: AuthKinds::Mac,
            password: String::from(""),
            vlan_enabled: false,
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

        entry.vlan_enabled = config.vlan_enabled;

        if entry.vlan_enabled {
            if config.vlan_id == 0 {
                entry.vlan_enabled = false;
                info!("VLAN not defined for entry: {:?} disabling vlan", entry);
            } else {
                if config.vlan_id > 4094 {
                    return Err(ConfigError::Message(
                        format!("Invalid VLAN id {:?} for entry {:?}", 
                        config.vlan_id, entry)
                    ));
                }
                entry.vlan = config.vlan_id;
            }
        }

        Ok((key,entry))
    }
    fn get_vlan(&self) -> Option<u16> {
        if self.vlan_enabled {
            Some(self.vlan)
        } else {
            None
        }
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

