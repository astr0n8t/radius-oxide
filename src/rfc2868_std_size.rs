use radius::core::avp::{AVPError, AVPType, AVP};
use radius::core::packet::Packet;
use radius::core::tag::Tag;


// Re-implementing these functions from here: https://github.com/moznion/radius-rs/blob/main/radius/src/core/rfc2868.rs
// For why see this issue: https://github.com/moznion/radius-rs/issues/35

fn from_tagged_u16(typ: AVPType, tag: Option<&Tag>, value: u16) -> AVP {
    let unused = Tag::new_unused();
    let tag = match tag {
        None => &unused,
        Some(tag) => tag,
    };
    let tag = vec![tag.get_value()];
    let val = u16::to_be_bytes(value as u16).to_vec();
    let offset = 6 - tag.len() - val.len() - 2;
    let value: Vec<u8>;
    if offset > 0 {
        value = [tag, vec![0; offset], val].concat();
    } else {
        value = [tag, val].concat();

    }
    AVP::from_bytes(typ, &value)
}

pub type TunnelType = u32;
pub type TunnelMediumType = u32;

pub const TUNNEL_MEDIUM_TYPE_TYPE: AVPType = 65;
/// Add `tunnel_medium_type` tagged value-defined integer value to a packet.
pub fn add_tunnel_medium_type(packet: &mut Packet, tag: Option<&Tag>, value: TunnelMediumType) {
    packet.add(from_tagged_u16(TUNNEL_MEDIUM_TYPE_TYPE, tag, value as u16));
}

pub const TUNNEL_TYPE_TYPE: AVPType = 64;
/// Add `tunnel_type` tagged value-defined integer value to a packet.
pub fn add_tunnel_type(packet: &mut Packet, tag: Option<&Tag>, value: TunnelType) {
    packet.add(from_tagged_u16(TUNNEL_TYPE_TYPE, tag, value as u16));
}

