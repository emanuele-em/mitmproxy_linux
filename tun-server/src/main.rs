use std::io::{Read, Write};

extern crate tun2;

fn main() {
    let mut config = tun2::Configuration::default();
    config.address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun2::create(&config).unwrap();
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        if let Ok(mut packet) = internet_packet::InternetPacket::try_from(Vec::from(&buf[0 .. amount])) {
            println!("{} {} {:x?}", packet.connection_id(), packet.tcp_flag_str(), packet.payload());
            if packet.tcp_flag_str() == "SYN" {
                let src = packet.src();
                packet.set_src(&packet.dst());
                packet.set_dst(&src);
                packet.set_tcp_flags(packet.tcp_flags() | 0x10);
                packet.set_tcp_acknowledgement_number(packet.tcp_sequence_number() + 1);
                packet.set_tcp_sequence_number(424242);
                packet.recalculate_ip_checksum();
                packet.recalculate_tcp_checksum();
                println!("{} {}", packet.connection_id(), packet.tcp_flag_str());
                dev.write(&packet.inner()).unwrap();
            }
        } else {
            println!("{:x?}", &buf[0 .. amount]);
        }
    }
}