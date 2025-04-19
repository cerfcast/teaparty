use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn authenticate(data: &[u8], key: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut hmacer = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Into::<std::io::Error>::into(std::io::ErrorKind::InvalidData))?;

    hmacer.update(data);
    Ok(hmacer.finalize().into_bytes()[0..16].to_vec())
}
