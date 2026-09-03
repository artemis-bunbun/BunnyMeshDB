//! Hand-rolled base64 / base64url (standard alphabets, no padding).
//! Encoding only — signatures are verified before any base64 decode is
//! trusted, so this is not a security boundary.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_impl(data: &[u8], alpha: &[u8; 64]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alpha[(n >> 18) as usize & 63] as char);
        out.push(alpha[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alpha[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(alpha[n as usize & 63] as char);
        }
    }
    out
}

fn decode_impl(s: &str, alpha: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut rev = [255u8; 128];
    for (i, &c) in alpha.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let valid: Vec<u8> = s
        .bytes()
        .map(|b| {
            if b >= 128 {
                Err(format!("non-ascii byte {b}"))
            } else if rev[b as usize] == 255 {
                Err(format!("invalid base64 char {:?}", b as char))
            } else {
                Ok(rev[b as usize])
            }
        })
        .collect::<Result<_, _>>()?;
    if valid.len() % 4 == 1 {
        return Err("invalid base64 length".into());
    }
    let mut out = Vec::with_capacity(valid.len() / 4 * 3);
    for chunk in valid.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= (c as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() == 4 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

pub fn b64_encode(data: &[u8]) -> String {
    encode_impl(data, B64)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    decode_impl(s, B64)
}

pub fn b64url_encode(data: &[u8]) -> String {
    encode_impl(data, B64URL)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    decode_impl(s, B64URL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg");
        assert_eq!(b64_encode(b"fo"), "Zm8");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(b64_decode("Zg").unwrap(), b"f");
        // url-safe alphabet roundtrip with binary data incl. 0xff
        let data = [0u8, 255, 128, 42, 13, 10];
        assert_eq!(b64url_decode(&b64url_encode(&data)).unwrap(), data);
        assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
        // error paths
        assert!(b64_decode("!!!!").is_err());
        assert!(b64_decode("a").is_err(), "mod-4 == 1 invalid");
        assert!(b64_decode("Zm9vYg==ünï").is_err());
    }

    #[test]
    fn url_alphabet_differs_from_standard() {
        // 0xfb -> standard '+' at tail, url-safe '-'
        let v = [0xfb, 0xff, 0x00];
        assert!(b64_encode(&v).contains('+'));
        assert!(!b64url_encode(&v).contains('+'));
        assert_eq!(b64url_decode(&b64url_encode(&v)).unwrap(), v);
    }
}