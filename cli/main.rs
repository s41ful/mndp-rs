use std::env;
use std::time::Duration;
use mndp_rs::{MndpConfig, };

fn parse_str_time(mut timeout: String) -> Duration {
    if timeout.ends_with("s") {
        timeout.pop();
        Duration::from_secs(timeout.parse().unwrap())
    } else {
        Duration::from_secs(20)
    }
}

fn print_help() {
    let permission = if cfg!(target_os = "windows") {
        "NPCAP driver & Administrator permission required"
    } else if cfg!(target_os = "linux") {
        "root or CAP_NET_RAW capability required"
    } else {
        "administrative privileges required" 
    };

    let help_message = format!(
r#"mndp-rs 0.1.0, Mikrotik Network Discovery Protocol
Usage:
    mndp [OPTIONS]

Options:
    -h, --help       show this help message
    -t <timeout>     set read timeout in seconds (default: 20s)
    -i <interface>   specify interface for listening directly in Ethernet frames ({})"#, 
        permission
    );

    println!("{}", help_message);
}

fn parse_args(args: Vec<String>) -> MndpConfig {
    let mut config = MndpConfig::new();

    for i in 0..args.len() {
        match args[i].as_str() {
            "-i" => {
                config.raw_socket = true;
                config.interface = Some(String::from(&args[i + 1]));
            },
            "-t" => {
                config.timeout = parse_str_time(String::from(&args[i + 1]))
            },
            "--help" | 
                "-h" |
                "help"=> {
                    print_help();
                    std::process::exit(1);
                }
            _ => {}
        }
    }

    config
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut listener: mndp_rs::Listener = mndp_rs::Listener::new(parse_args(args)); 
    println!("Devices: {:?}", listener.discover())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_str_time() {
        let result = parse_str_time(String::from("5s"));
        assert_eq!(result, Duration::from_secs(5));
    }

    #[test]
    fn test_parse_args() {
        let result = parse_args(vec!["./mndp", "-t", "6s", "-i", "enp3s0"].iter().map(|s| {
            s.to_string()
        }).collect());
        assert_eq!(result, MndpConfig { interface: Some(String::from("enp3s0")), timeout: Duration::from_secs(6), raw_socket: true})
    }
}
