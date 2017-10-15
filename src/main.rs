extern crate pcap;
extern crate pnet;

use std::io::ErrorKind;
use pcap::{Device, Error};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::FromPacket;

fn capture() -> Result<(), Error> {
    //let mut cap = Device::lookup()?.open()?;

    Device::list()?.into_iter().for_each(|x| println!("{:?}", x));

    println!("Take en1");

    //Maybe promiscuous mode is mandatory
    let mut cap = Device::list()?.into_iter()
                                 .find(|&ref x| x.name == "en1")
                                 .ok_or(Error::IoError(ErrorKind::NotFound))?
                                 .open()?;
    cap.filter("arp")?;

    while let Ok(packet) = cap.next() {
        println!("arp captured");
        if let Some(eframe) = EthernetPacket::new(packet.data) {
            let ethernet = eframe.from_packet();
            println!("received packet: {:?}", ethernet);
        }
    }

    Ok(())
}

fn main() {
    println!("Hello, world!");
    println!("{:?}", capture());
}
