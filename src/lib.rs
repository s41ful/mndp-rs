use std::env;
use std::error::Error;
use std::time::Duration;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io::{self, ErrorKind};
use std::io::{Cursor, Read};

use socket2::{Domain, Protocol, Socket, Type};

use pnet::datalink::{self, Config};
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
pub struct Device {
    pub identity: String,
    pub mac_address: MacAddr,
    pub version: String,
    pub platform: String,
    pub uptime: Duration,
    pub software_id: String,
    pub board: String,
    pub unpack: Vec<u8>,
    pub ipv6_address: Ipv6Addr,
    pub interface_name: String,
    pub ipv4_address: Ipv4Addr,
}

impl Device {
    pub fn new() -> Self {
        Self { 
            identity: String::new(), 
            mac_address: MacAddr::new(0, 0, 0, 0, 0, 0), 
            version: String::new(),
            platform: String::new(),
            uptime: Duration::new(0, 0),
            software_id: String::new(),
            board: String::new(),
            unpack: Vec::new(),
            ipv6_address: Ipv6Addr::new(6, 0, 0, 0, 0, 0, 0, 0),
            interface_name: String::new(),
            ipv4_address: Ipv4Addr::new(0, 0, 0, 0)
        }
    }
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

#[derive(PartialEq, Debug)]
pub enum MndpError {
    InterfaceNotFound,
    InterfaceDoesNotSpecified,
}

impl From<MndpPacket> for Device {
    fn from(packet: MndpPacket) -> Self {
        let mut device = Device::new();
        let _ = packet.parts.iter().map(|part| {
            match part.ty {
               MndpTlvType::MacAddress => if let MndpValue::Mac(mac) = part.value { device.mac_address = mac },
               MndpTlvType::Identity => if let MndpValue::String(ref identity) = part.value { device.identity = identity.clone()},
               MndpTlvType::Version => if let MndpValue::String(ref version) = part.value { device.version = version.clone() },
               MndpTlvType::Platform => if let MndpValue::String(ref platform) = part.value { device.platform = platform.clone() },
               MndpTlvType::Uptime => if let MndpValue::Uptime(duration) = part.value { device.uptime = duration },
               MndpTlvType::Board => if let MndpValue::Mac(mac) = part.value { device.mac_address = mac },
               MndpTlvType::SoftwareId => if let MndpValue::String(ref software_id) = part.value { device.software_id = software_id.clone() },
               MndpTlvType::Unpack => if let MndpValue::Uptime(dur) = part.value { device.uptime = dur },
               MndpTlvType::IPv4Address => if let MndpValue::Ipv4(ip4) = part.value { device.ipv4_address = ip4 },
               MndpTlvType::InterfaceName => if let MndpValue::String(ref interface) = part.value { device.interface_name = interface.clone() },
               MndpTlvType::IPv6Address => if let MndpValue::Ipv6(ipv6) = part.value { device.ipv6_address = ipv6 },
                _ => {},
            }
        });

        device
    }
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

pub fn decode(buf: &[u8]) -> std::io::Result<Device> {
    if buf.is_empty() {
        ()
    }

    let mut cur = Cursor::new(buf);

    let _seq_no = read_u32_le(&mut cur)?;
    // let mut parts = Vec::new();
    let mut device = Device::new();

    while (cur.position() as usize) < buf.len() {
        let ty = MndpTlvType::from(read_u16_be(&mut cur)?);
        let len = read_u16_be(&mut cur)? as usize;

        match ty {
            MndpTlvType::MacAddress => {
                let mut mac = [0u8; 6];
                cur.read_exact(&mut mac)?;
                device.mac_address = MacAddr::from(mac);
            }

            MndpTlvType::Identity => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                device.identity = String::from_utf8_lossy(&bytes).into_owned();
            }

            MndpTlvType::Version => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                device.version = String::from_utf8_lossy(&bytes).into_owned();
            }
            MndpTlvType::Platform => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                device.platform = String::from_utf8_lossy(&bytes).into_owned();
            }
            MndpTlvType::SoftwareId => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                device.software_id = String::from_utf8_lossy(&bytes).into_owned();
            }
            MndpTlvType::Board => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                device.board = String::from_utf8_lossy(&bytes).into_owned();
            }
            MndpTlvType::InterfaceName => {
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
                device.interface_name = String::from_utf8_lossy(&bytes).into_owned();
            }

            MndpTlvType::Uptime => {
                let secs = read_u32_le(&mut cur)?;
                device.uptime = Duration::from_secs(secs as u64);
            }

            MndpTlvType::IPv4Address => {
                let mut ip = [0u8; 4];
                cur.read_exact(&mut ip)?;
                device.ipv4_address = Ipv4Addr::from(ip);
            }

            MndpTlvType::IPv6Address => {
                let mut ip = [0u8; 16];
                cur.read_exact(&mut ip)?;
                device.ipv6_address = Ipv6Addr::from(ip);
            }

            _ => { 
                let mut bytes = vec![0; len];
                cur.read_exact(&mut bytes)?;
            }
        };
    }

    Ok(device)
}

pub fn bind_and_listen(timeout: Duration) -> Result<Vec<Device>, MndpError> {
    let addr: SocketAddr = "0.0.0.0:5678".parse().unwrap();
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    socket.set_reuse_address(true).unwrap();
    socket.bind(&addr.into()).unwrap();
    socket.set_read_timeout(Some(timeout)).unwrap();

    let mut buff = Vec::with_capacity(1024);
    println!("Listening on {:?}", addr);
    let mut devices: Vec<Device> = Vec::new();

    loop {
        match socket.recv_from(buff.spare_capacity_mut()) {
            Ok((readed, peer)) => {
                unsafe {
                    buff.set_len(readed);
                }
                println!("Getting connection, readed {} bytes, from: {:?}", readed, peer.as_socket().unwrap());

                match decode(&buff[..]) {
                    Ok(mndp_packet) => {
                        println!("{:?}", mndp_packet);
                        devices.push(mndp_packet);
                    } 
                    Err(err) => println!("error while decoding packet {err}")
                }

            } 
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => { return Ok(devices); }

            _ => {}
        }
    }
}

fn get_ipv4_packet<'a>(ether_packet: &'a EthernetPacket<'a>) -> Result<Ipv4Packet<'a>, ()>{
    if ether_packet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(ipv4_packet) = Ipv4Packet::new(ether_packet.payload()) {
            return Ok(ipv4_packet);
        }
    }
    Err(())
}

fn get_udp_packet<'a>(ip_packet: &'a Ipv4Packet<'a>) -> Result<UdpPacket<'a>, ()> {
    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
        if let Some(udp_packet) = UdpPacket::new(ip_packet.payload()) {
            return Ok(udp_packet)
        }
    }
    Err(())
}

pub fn listen_on_raw_socket(timeout: Duration) -> Result<Vec<Device>, MndpError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: sudo cargo run -- <interface_name>");
        println!("Available interface:");
        for iface in datalink::interfaces() {
            println!(" - {}", iface.name);
        }
        return Err(MndpError::InterfaceDoesNotSpecified);
    }

    let interface_name = &args[1];
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == *interface_name)
        .next()
        .expect("Interface not found!");

    let mut config: Config = Default::default();
    config.read_timeout = Some(timeout);

    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    println!("Listening & Filtering packet in {}...", interface.name);
    let mut devices: Vec<Device> = Vec::new();

    loop {
        match rx.next() {
            Ok(packet) => {
                let Some(ethernet_packet) = EthernetPacket::new(packet) else { continue };
                let Ok(ipv4_packet) = get_ipv4_packet(&ethernet_packet) else { continue };
                let Ok(udp_packet) = get_udp_packet(&ipv4_packet) else { continue };
                match udp_packet.get_destination() {
                    5678 => {
                        println!(
                            "[MNDP] {}:{} -> {}:{}",
                            ipv4_packet.get_source(),
                            udp_packet.get_source(),
                            ipv4_packet.get_destination(),
                            udp_packet.get_destination()
                        );
                        match decode(udp_packet.payload()) {
                            Ok(mndp_packet) => {
                                println!("{:?}", mndp_packet);
                                devices.push(mndp_packet);
                            } 
                            Err(err) => println!("decode err: {err}")
                        }
                    },
                    _ => {}
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => { return Ok(devices); }
            _ => {}
        }
    }
}

pub fn discover( /* TODO: add timeout parameter */ ) {

}
