#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    pub flags: u8,
    pub tpe: u8,
    pub length: u16,
    pub value: Vec<u8>,
}
impl From<&Tlv> for Vec<u8> {
    fn from(raw: &Tlv) -> Vec<u8> {
        let mut result = vec![0u8; 1 + 1 + 2 + raw.length as usize];
        result[0] = raw.flags;
        result[1] = raw.tpe;
        result[2..4].copy_from_slice(&raw.length.to_be_bytes());
        result[4..4 + raw.length as usize].copy_from_slice(raw.value.as_slice());
        result
    }
}
impl From<Tlv> for Vec<u8> {
    fn from(raw: Tlv) -> Vec<u8> {
        From::<&Tlv>::from(&raw)
    }
}

impl TryFrom<&[u8]> for Tlv {
    type Error = std::io::Error;

    fn try_from(raw: &[u8]) -> Result<Self, std::io::Error> {
        let mut raw_idx = 0usize;
        let flags = raw[raw_idx];
        raw_idx += 1;

        if raw_idx >= raw.len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let tpe = raw[raw_idx];
        raw_idx += 1;

        if raw_idx + 2 >= raw.len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let length = u16::from_be_bytes(raw[raw_idx..raw_idx + 2].try_into().unwrap());
        raw_idx += 2;

        if raw_idx + (length as usize) > raw.len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        let mut value = vec![0; length as usize];
        value.copy_from_slice(&raw[raw_idx..raw_idx + (length as usize)]);

        Ok(Tlv {
            flags,
            tpe,
            length,
            value,
        })
    }
}

impl Tlv {
    pub fn extra_padding(len: u16) -> Self {
        Tlv {
            flags: 0x0,
            tpe: 0x1,
            length: len,
            value: vec![0u8; len as usize],
        }
    }
}
