#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketDirection {
    Ingress,
    Egress,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub enum PacketEvent {
    Connect {
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        direction: PacketDirection,
    },
    Traffic {
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
        direction: PacketDirection,
        payload: [u8; 64],
    },
    Disconnect {
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        direction: PacketDirection,
    },
    ConnectFunc {
        destination_ip: u32,
        pid: u32,
        destination_port: u16,
        padd: u16, // just used for padding, otherwise the load will complain. See point #10: https://docs.cilium.io/en/v1.7/bpf/
    },
    AcceptFunc {
        source_ip: u32,
        pid: u32,
        source_port: u16,
        padd: u16, // just used for padding, otherwise the load will complain. See point #10: https://docs.cilium.io/en/v1.7/bpf/
    },
}
impl PacketEvent {
    #[inline]
    pub fn new_connect(
        remote_ip: u32,
        local_port: u16,
        remote_port: u16,
        direction: PacketDirection,
    ) -> Self {
        Self::Connect {
            remote_ip,
            local_port,
            remote_port,
            direction,
        }
    }

    #[inline]
    pub fn new_disconnect(
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        direction: PacketDirection,
    ) -> Self {
        Self::Disconnect {
            remote_ip,
            remote_port,
            local_port,
            direction,
        }
    }
    #[inline]
    pub fn new_traffic(
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        payload_size: u16,
        direction: PacketDirection,
        payload: [u8; 64],
    ) -> Self {
        Self::Traffic {
            remote_ip,
            remote_port,
            local_port,
            payload_size,
            direction,
            payload,
        }
    }
    #[inline]
    pub fn new_connect_func(destination_ip: u32, destination_port: u16, pid: u32) -> Self {
        Self::ConnectFunc {
            destination_ip,
            destination_port,
            pid,
            padd: 0,
        }
    }
    #[inline]
    pub fn new_accept_func(source_ip: u32, source_port: u16, pid: u32) -> Self {
        Self::AcceptFunc {
            source_ip,
            source_port,
            pid,
            padd: 0,
        }
    }
}

#[cfg(feature = "user")]
mod userspace {
    use super::*;
    unsafe impl Pod for PacketEvent {}
}
