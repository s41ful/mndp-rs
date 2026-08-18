use std::io::{self, ErrorKind};
use std::io::{Cursor, Read};
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::mpsc;

use pnet::datalink::Channel;
use pnet::datalink::{self, Config};
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;

static MNDP_LISTEN_PORT: &str = "0.0.0.0:5678";

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

#[derive(Debug, PartialEq, Clone)]
pub struct MndpConfig {
    pub interface: Option<String>,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct Listener {
    pub config: MndpConfig,
}

impl MndpConfig {
    pub fn new() -> Self {
        Self {
            interface: None,
            timeout: Duration::from_secs(20),
        }
    }
}

impl Default for MndpConfig {
    fn default() -> Self {
        Self::new()
    }
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
            ipv4_address: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
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

#[derive(Debug)]
pub enum MndpError {
    ParseAddrError(AddrParseError),
    Other(std::io::Error),
    InterfaceNotFound,
    InterfaceDoesNotSpecified,
    UnsupportedChannel,
    EthernetChannelError(std::io::Error),
}

impl From<MndpPacket> for Device {
    fn from(packet: MndpPacket) -> Self {
        let mut device = Device::new();
        let _ = packet.parts.iter().map(|part| match part.ty {
            MndpTlvType::MacAddress => {
                if let MndpValue::Mac(mac) = part.value {
                    device.mac_address = mac
                }
            }
            MndpTlvType::Identity => {
                if let MndpValue::String(ref identity) = part.value {
                    device.identity = String::from(identity)
                }
            }
            MndpTlvType::Version => {
                if let MndpValue::String(ref version) = part.value {
                    device.version = String::from(version)
                }
            }
            MndpTlvType::Platform => {
                if let MndpValue::String(ref platform) = part.value {
                    device.platform = String::from(platform)
                }
            }
            MndpTlvType::Uptime => {
                if let MndpValue::Uptime(duration) = part.value {
                    device.uptime = duration
                }
            }
            MndpTlvType::Board => {
                if let MndpValue::Mac(mac) = part.value {
                    device.mac_address = mac
                }
            }
            MndpTlvType::SoftwareId => {
                if let MndpValue::String(ref software_id) = part.value {
                    device.software_id = String::from(software_id)
                }
            }
            MndpTlvType::Unpack => {
                if let MndpValue::Uptime(dur) = part.value {
                    device.uptime = dur
                }
            }
            MndpTlvType::IPv4Address => {
                if let MndpValue::Ipv4(ip4) = part.value {
                    device.ipv4_address = ip4
                }
            }
            MndpTlvType::InterfaceName => {
                if let MndpValue::String(ref interface) = part.value {
                    device.interface_name = String::from(interface)
                }
            }
            MndpTlvType::IPv6Address => {
                if let MndpValue::Ipv6(ipv6) = part.value {
                    device.ipv6_address = ipv6
                }
            }
            _ => {}
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
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty buffer",
        ));
    }

    let mut cur = Cursor::new(buf);
    let _seq_no = read_u32_le(&mut cur)?;
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

fn bind_and_listen(timeout: Duration) -> Result<Option<Vec<Device>>, MndpError> {
    let addr: SocketAddr = MNDP_LISTEN_PORT
        .parse()
        .map_err(MndpError::ParseAddrError)?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(MndpError::Other)?;

    socket.set_reuse_address(true).map_err(MndpError::Other)?;
    socket.bind(&addr.into()).map_err(MndpError::Other)?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(MndpError::Other)?;

    let mut buff = Vec::with_capacity(1024);
    let mut devices: Vec<Device> = Vec::new();

    loop {
        match socket.recv_from(buff.spare_capacity_mut()) {
            Ok((readed, _peer)) => {
                unsafe {
                    buff.set_len(readed);
                }

                match decode(&buff[..]) {
                    Ok(mndp_packet) => {
                        println!("{:?}", mndp_packet);
                        devices.push(mndp_packet);
                    }
                    Err(_) => {}
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if devices.is_empty() {
                    return Ok(None);
                } else {
                    return Ok(Some(devices));
                }
            }

            _ => {}
        }
    }
}

fn get_ipv4_packet<'a>(ether_packet: &'a EthernetPacket<'a>) -> Result<Ipv4Packet<'a>, ()> {
    if ether_packet.get_ethertype() == EtherTypes::Ipv4
        && let Some(ipv4_packet) = Ipv4Packet::new(ether_packet.payload())
    {
        return Ok(ipv4_packet);
    }

    Err(())
}

fn get_udp_packet<'a>(ip_packet: &'a Ipv4Packet<'a>) -> Result<UdpPacket<'a>, ()> {
    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
        && let Some(udp_packet) = UdpPacket::new(ip_packet.payload())
    {
        return Ok(udp_packet);
    }

    Err(())
}

fn listen_on_raw_socket(
    timeout: Duration,
    interface: &String,
) -> Result<Option<Vec<Device>>, MndpError> {
    let interface_name = interface;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .expect("Interface not found!");

    let config: Config = Config {
        read_timeout: Some(timeout),
        ..Default::default()
    };

    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(MndpError::UnsupportedChannel),
        Err(e) => return Err(MndpError::EthernetChannelError(e)),
    };

    let mut devices: Vec<Device> = Vec::new();

    loop {
        match rx.next() {
            Ok(packet) => {
                let Some(ethernet_packet) = EthernetPacket::new(packet) else {
                    continue;
                };
                let Ok(ipv4_packet) = get_ipv4_packet(&ethernet_packet) else {
                    continue;
                };
                let Ok(udp_packet) = get_udp_packet(&ipv4_packet) else {
                    continue;
                };
                if udp_packet.get_destination() == 5678 {
                    match decode(udp_packet.payload()) {
                        Ok(mndp_packet) => {
                            devices.push(mndp_packet);
                        }
                        Err(_) => {}
                    }
                }
            }

            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if devices.is_empty() {
                    return Ok(None);
                } else {
                    return Ok(Some(devices));
                }
            }
            _ => {}
        }
    }
}

impl Listener {
    pub fn new(config: MndpConfig) -> Self {
        Self { config }
    }

    pub fn start_discovery_stream(&self) -> mpsc::Receiver<Device> {
        let (tx, rx) = mpsc::channel::<Device>(100);
        let config = self.config.clone();

        tokio::task::spawn_blocking(move || {
            let start_time = Instant::now();
            let total_timeout = config.timeout;

            loop {
                if start_time.elapsed() >= total_timeout {
                    break;
                }

                let micro_timeout = Duration::from_millis(100);

                let result = if config.interface.is_some() {
                    listen_on_raw_socket(micro_timeout, config.interface.as_ref().unwrap())
                } else {
                    bind_and_listen(micro_timeout)
                };

                if let Ok(Some(devices)) = result {
                    for device in devices {
                        if tx.blocking_send(device).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        rx
    }

    pub fn discover(&self) -> Result<Option<Vec<Device>>, MndpError> {
        if self.config.interface.is_some() {
            listen_on_raw_socket(self.config.timeout, self.config.interface.as_ref().unwrap())
        } else {
            bind_and_listen(self.config.timeout)
        }
    }
}
