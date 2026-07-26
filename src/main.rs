use std::env;
use std::time::Duration;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::io;
use std::io::{Cursor, Read};

use pnet::datalink;
use pnet::datalink::Channel;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;

#[derive(Debug)]
pub struct MndpPacket {
    pub seq_no: u32,
    pub parts: Vec<MndpPart>,
}

#[derive(Debug)]
pub struct MndpPart {
    pub ty: MndpTlvType,
    pub value: MndpValue,
}

#[derive(Debug)]
pub enum MndpValue {
    Mac(MacAddr),
    String(String),
    Uptime(Duration),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
pub enum MndpTlvType {
    MacAddress,
    Identity,
    Version,
    Platform,
    Uptime,
    SoftwareId,
    Board,
    Unpack,
    IPv6Address,
    InterfaceName,
    IPv4Address,
    Unknown(u16),
}

impl From<u16> for MndpTlvType {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::MacAddress,
            5 => Self::Identity,
            7 => Self::Version,
            8 => Self::Platform,
            10 => Self::Uptime,
            11 => Self::SoftwareId,
            12 => Self::Board,
            14 => Self::Unpack,
            15 => Self::IPv6Address,
            16 => Self::InterfaceName,
            17 => Self::IPv4Address,
            _ => Self::Unknown(v),
        }
    }
}

fn read_u16_be(r: &mut Cursor<&[u8]>) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32_le(r: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub fn decode_packet(buf: &[u8]) -> std::io::Result<MndpPacket> {
    let mut cur = Cursor::new(buf);

    let seq_no = read_u32_le(&mut cur)?;
    let mut parts = Vec::new();

    while (cur.position() as usize) < buf.len() {
        let ty = MndpTlvType::from(read_u16_be(&mut cur)?);
        let len = read_u16_be(&mut cur)? as usize;

        let value = match ty {
            MndpTlvType::MacAddress => {
                let mut mac = [0u8; 6];
                cur.read_exact(&mut mac)?;
                MndpValue::Mac(MacAddr::from(mac))
            }

            MndpTlvType::Identity
            | MndpTlvType::Version
            | MndpTlvType::Platform
            | MndpTlvType::SoftwareId
            | MndpTlvType::Board
            | MndpTlvType::InterfaceName => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                MndpValue::String(String::from_utf8_lossy(&bytes).into_owned())
            }

            MndpTlvType::Uptime => {
                let secs = read_u32_le(&mut cur)?;
                MndpValue::Uptime(Duration::from_secs(secs as u64))
            }

            MndpTlvType::IPv4Address => {
                let mut ip = [0u8; 4];
                cur.read_exact(&mut ip)?;
                MndpValue::Ipv4(Ipv4Addr::from(ip))
            }

            MndpTlvType::IPv6Address => {
                let mut ip = [0u8; 16];
                cur.read_exact(&mut ip)?;
                MndpValue::Ipv6(Ipv6Addr::from(ip))
            }

            _ => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                MndpValue::Bytes(bytes)
            }
        };

        parts.push(MndpPart { ty, value });
    }

    Ok(MndpPacket { seq_no, parts })
}

fn main() -> () {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: sudo cargo run -- <nama_interface>");
        println!("Avaliable interface:");
        for iface in datalink::interfaces() {
            println!(" - {}", iface.name);
        }
        return;
    }
    let interface_name = &args[1];

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == *interface_name)
        .next()
        .expect("Interface not found!");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    println!("Listening & Filtering packet in {}...", interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                            let src_ip = ipv4_packet.get_source();
                            let dst_ip = ipv4_packet.get_destination();
                            match ipv4_packet.get_next_level_protocol() {
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload())
                                    {
                                        match udp_packet.get_destination() {
                                            5678 => {
                                                println!(
                                                    "[UDP] {}:{} -> {}:{}",
                                                    src_ip,
                                                    udp_packet.get_source(),
                                                    dst_ip,
                                                    udp_packet.get_destination()
                                                );
                                                match decode_packet(udp_packet.payload()) {
                                                    Ok(mndp_packet) => {
                                                        println!("{:?}", mndp_packet)
                                                    } 
                                                    Err(err) => println!("{err}")
                                                }
                                            },
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Failed to receive packet: {}", e),
        }
    }
}
