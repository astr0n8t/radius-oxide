#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::io;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use radius::core::code::Code;
use radius::core::tag::Tag;
use radius::core::request::Request;
use radius::core::{rfc2865, rfc2868};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError};

pub mod settings;
pub mod rfc2868_std_size;

pub struct OxideRequestHandler {
    settings: settings::OxideSettings,
}

impl OxideRequestHandler {
    pub fn new(settings: settings::OxideSettings) -> Self {
        Self { settings }
    }
}

#[async_trait]
impl RequestHandler<(), io::Error> for OxideRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        // If the server is not in the whitelist, log the attempt, but return immediately
        if !self.settings.valid_server(req.get_remote_addr()) {
            warn!("Received request from server not in whitelist: {}", req.get_remote_addr());
            return Ok(())
        }
        // Otherwise continue processing
        let req_packet = req.get_packet();
        let maybe_user_name_attr = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password_attr = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name_attr.unwrap().unwrap();
        let user_password = String::from_utf8(maybe_user_password_attr.unwrap().unwrap()).unwrap();

        let (authenticated, mut vlan) = self.settings.authenticate(&user_name, &user_password);

        let code;
        if authenticated {
            code = Code::AccessAccept
        } else if let Some(default_vlan) = self.settings.get_server_default_vlan(req.get_remote_addr()) {
            vlan = Some(default_vlan);
            code = Code::AccessAccept;
        } else {
            code = Code::AccessReject
        };
        info!("response => {:?} to {} for client {}", code, req.get_remote_addr(), user_name);

        // VLAN attributes
        let mut response = req_packet.make_response_packet(code);

        // Strip client added values
        rfc2868::delete_tunnel_type(&mut response);
        rfc2868::delete_tunnel_medium_type(&mut response);
        rfc2868::delete_tunnel_private_group_id(&mut response);

        // Insert server values
        if code == Code::AccessAccept && vlan.is_some() {
            let vlan = vlan.unwrap();
            let tunnel_tag = Tag::new(1);
            // VLAN
            rfc2868_std_size::add_tunnel_type(&mut response, Some(&tunnel_tag), 13);
            // Tunnel-Medium-Type        IEEE-802        6
            rfc2868_std_size::add_tunnel_medium_type(&mut response, Some(&tunnel_tag), 6);
            rfc2868::add_tunnel_private_group_id(&mut response, Some(&tunnel_tag), &vlan.to_string());
        }

        conn.send_to(
            &response.encode().unwrap(),
            req.get_remote_addr(),
        )
        .await?;
        Ok(())
    }
}

pub struct OxideSecretProvider {
    secret: String,
}
impl OxideSecretProvider {
    pub fn new(secret: &str) -> Self {
        Self { secret: String::from(secret) }
    }
}

impl SecretProvider for OxideSecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(self.secret.clone().into_bytes())
    }
}

