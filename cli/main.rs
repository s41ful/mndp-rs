use std::env;
use mndp_rs::parse_args;

fn main() -> () {
    let args: Vec<String> = env::args().collect();
    let mut listener: mndp_rs::Listener = mndp_rs::Listener::new(parse_args(args)); 
    println!("Devices: {:?}", listener.discover())
}
