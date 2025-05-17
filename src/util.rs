use std::net::{SocketAddr, SocketAddrV6};

use hmac::{Hmac, Mac};
use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};
use sha2::Sha256;

pub fn authenticate(data: &[u8], key: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut hmacer = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Into::<std::io::Error>::into(std::io::ErrorKind::InvalidData))?;

    hmacer.update(data);
    Ok(hmacer.finalize().into_bytes()[0..16].to_vec())
}

pub fn to_sockaddr_storage(sock: SocketAddr) -> SockaddrStorage {
    match sock {
        SocketAddr::V4(v4) => Into::<SockaddrStorage>::into(v4),
        SocketAddr::V6(v6) => Into::<SockaddrStorage>::into(v6),
    }
}

pub fn to_socketaddr(storage: SockaddrStorage) -> SocketAddr {
    match storage.family().unwrap() {
        AddressFamily::Inet => SocketAddr::from((
            storage.as_sockaddr_in().unwrap().ip(),
            storage.as_sockaddr_in().unwrap().port(),
        )),
        AddressFamily::Inet6 => SocketAddrV6::new(
            storage.as_sockaddr_in6().unwrap().ip(),
            storage.as_sockaddr_in6().unwrap().port(),
            0,
            0,
        )
        .into(),
        _ => {
            todo!("Unsupported network address detected.")
        }
    }
}
