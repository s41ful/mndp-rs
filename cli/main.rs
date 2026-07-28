use std::time::Duration;

fn main() -> () {
    mndp_rs::bind_and_listen(Duration::from_secs(5)).unwrap();

    ()
}
