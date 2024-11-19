use crate::server::ServerSocket;
use slog::Logger;
use std::net::SocketAddr;

#[derive(Debug, Clone, Default)]
pub struct MacAddr {
    pub mac: [u8; 6],
}

#[cfg(target_os = "linux")]
mod linux_support {

    use nix::{
        libc::{self, RTA_DST, RTA_OIF, RTM_GETROUTE, RTM_NEWROUTE},
        sys::socket::{bind, recvmsg, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag},
    };
    use slog::{info, Logger};
    use std::{io::IoSliceMut, net::SocketAddr, os::fd::AsRawFd};

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union HwReqData {
        pub addr: libc::sockaddr,
        pub index: i32,
    }

    #[repr(C)]
    pub struct HwReq {
        pub name: [u8; 16],
        pub data: HwReqData,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct NlMsgHdr {
        len: u32,
        tpe: u16,
        flags: u16,
        seq: u32,
        pid: u32,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct RtMsg {
        family: libc::c_uchar,
        dst_len: libc::c_uchar,
        src_len: libc::c_uchar,
        tos: libc::c_uchar,
        table: libc::c_uchar,
        protocol: libc::c_uchar,
        scope: libc::c_uchar,
        tpe: libc::c_uchar,
        flags: u32,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct GetRoute {
        nl: NlMsgHdr,
        msg: RtMsg,
        attr_len: u16,
        attr_type: u16,
        value: [u8; 16],
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct RtAttrHdr {
        len: u16,
        tpe: u16,
    }

    pub fn get_outgoing_interface(
        addr: crate::SocketAddr,
        logger: Logger,
    ) -> Result<i32, std::io::Error> {
        let nl_socket = socket(
            AddressFamily::Netlink,
            nix::sys::socket::SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            nix::sys::socket::SockProtocol::NetlinkRoute,
        )?;

        bind(nl_socket.as_raw_fd(), &NetlinkAddr::new(0, 0))?;

        let mut msg = GetRoute {
            ..Default::default()
        };

        let nl_packet_size = 28u32;
        let nl_attribute_size = if addr.is_ipv4() { 8 } else { 20 };
        match addr {
            SocketAddr::V4(v4) => msg.value[0..4].copy_from_slice(&v4.ip().octets()),
            SocketAddr::V6(v6) => msg.value.copy_from_slice(&v6.ip().octets()),
        };

        msg.nl.flags = 0x1;
        msg.nl.tpe = RTM_GETROUTE;
        msg.nl.len = nl_packet_size + nl_attribute_size;
        msg.nl.seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| std::io::ErrorKind::AddrNotAvailable)?
            .as_secs() as u32;
        msg.msg.family = if addr.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        } as libc::c_uchar;
        msg.msg.dst_len = 32;
        msg.msg.src_len = 0;
        msg.attr_len = nl_attribute_size as u16;
        msg.attr_type = RTA_DST;

        unsafe {
            libc::send(
                nl_socket.as_raw_fd(),
                &mut msg as *const GetRoute as *const libc::c_void,
                nl_packet_size as usize + nl_attribute_size as usize,
                0,
            );
        }

        let mut recv_buffer = [0u8; 1000];
        let recv_buffer_iov = IoSliceMut::new(&mut recv_buffer);

        let mut iovs = [recv_buffer_iov];

        let recvd =
            recvmsg::<NetlinkAddr>(nl_socket.as_raw_fd(), &mut iovs, None, MsgFlags::empty())?;
        for iov in recvd.iovs() {
            unsafe {
                let getr = iov.as_ptr() as *const GetRoute;
                let nl_total_size = (*getr).nl.len;
                if (*getr).nl.tpe != RTM_NEWROUTE {
                    continue;
                }

                if nl_total_size > iov.len() as u32 {
                    continue;
                }
            }

            let iov_len = iov.len() - nl_packet_size as usize;
            let mut rta_start = nl_packet_size;

            while (rta_start as usize) < iov_len {
                unsafe {
                    let hdr = iov[rta_start as usize..].as_ptr() as *const RtAttrHdr;

                    if (*hdr).tpe == RTA_OIF {
                        let ofi: *const i32 = iov[rta_start as usize + 4..].as_ptr() as *const i32;
                        info!(logger, "outgoing interface index (when getting MAC address for heartbeats): {}", *ofi);
                        return Ok(*ofi);
                    }

                    rta_start += (*hdr).len as u32;
                }
            }
        }
        Err(std::io::ErrorKind::AddrNotAvailable.into())
    }
}

#[cfg(target_os = "linux")]
pub fn get_mac_address(
    socket: ServerSocket,
    addr: SocketAddr,
    logger: Logger,
) -> Result<MacAddr, std::io::Error> {
    use nix::{ioctl_read_bad, libc};
    use std::os::fd::AsRawFd;

    let iface_index = linux_support::get_outgoing_interface(addr, logger.clone())?;

    ioctl_read_bad!(read_mac_ioctl, 0x8927, linux_support::HwReq);
    ioctl_read_bad!(read_name_ioctl, 0x8910, linux_support::HwReq);

    let socket = socket.socket.lock().unwrap();

    let mut addr_req = linux_support::HwReq {
        name: Default::default(),
        data: linux_support::HwReqData {
            addr: libc::sockaddr {
                sa_data: [0; 14],
                sa_family: Default::default(),
            },
        },
    };

    let mut name_req = linux_support::HwReq {
        name: Default::default(),
        data: linux_support::HwReqData { index: iface_index },
    };

    unsafe {
        read_name_ioctl(socket.as_raw_fd(), &mut name_req)?;
        addr_req.name.copy_from_slice(&name_req.name);
        let mut mac: [u8; 6] = [0; 6];
        read_mac_ioctl(socket.as_raw_fd(), &mut addr_req)?;
        addr_req
            .data
            .addr
            .sa_data
            .iter()
            .take(6)
            .enumerate()
            .for_each(|(i, v)| mac[i] = *v as u8);
        Ok(MacAddr { mac })
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_mac_address(
    _: ServerSocket,
    _: SocketAddr,
    logger: Logger,
) -> Result<MacAddr, std::io::Error> {
    use rand::prelude::*;
    use slog::info;

    let mut mac: [u8; 6] = [0u8; 6];
    mac.iter_mut().for_each(|v| *v = random());

    info!(logger, "Note: No support for getting a mac address on this platform. Using randomness instead ({:x?}).", mac);

    Ok(MacAddr { mac })
}
