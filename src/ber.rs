/// Minimal BER encoder/decoder for the subset of ASN.1 used by LDAP.

#[derive(Debug)]
pub enum BerError {
    UnexpectedEof,
    LongFormTag,
    UnexpectedTag { expected: u8, got: u8 },
    InvalidUtf8,
    LengthOutOfRange,
    NestingTooDeep,
    InvalidValue,
}

impl std::fmt::Display for BerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof    => write!(f, "Unexpected end of input"),
            Self::LongFormTag      => write!(f, "Long-form tag not supported"),
            Self::UnexpectedTag { expected, got }
                                   => write!(f, "Unexpected tag: expected {expected:#04x}, got {got:#04x}"),
            Self::InvalidUtf8      => write!(f, "Invalid UTF-8"),
            Self::LengthOutOfRange => write!(f, "Length out of range"),
            Self::NestingTooDeep   => write!(f, "Filter nesting too deep"),
            Self::InvalidValue     => write!(f, "Invalid value"),
        }
    }
}

impl std::error::Error for BerError {}

pub type BerResult<T> = Result<T, BerError>;

// Universal tags
pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_ENUMERATED: u8 = 0x0a;
pub const TAG_SEQUENCE: u8 = 0x30; // constructed
pub const TAG_SET: u8 = 0x31;      // constructed

// Encoding

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len < 0x1000000 {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn encode_integer(n: i64) -> Vec<u8> {
    encode_tlv(TAG_INTEGER, &integer_content(n))
}

/// Minimal two's-complement big-endian content octets for `n`.
fn integer_content(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let raw = n.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        // Strip leading 0x00 when next byte's high bit is clear
        if raw[start] == 0x00 && raw[start + 1] & 0x80 == 0 {
            start += 1;
        // Strip leading 0xff when next byte's high bit is set
        } else if raw[start] == 0xff && raw[start + 1] & 0x80 != 0 {
            start += 1;
        } else {
            break;
        }
    }
    raw[start..].to_vec()
}

/// ENUMERATED shares INTEGER's content encoding; LDAP result codes are
/// non-negative, so the value is encoded as an unsigned quantity.
pub fn encode_enumerated(n: u32) -> Vec<u8> {
    encode_tlv(TAG_ENUMERATED, &integer_content(n as i64))
}

pub fn encode_octet_string(s: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, s)
}

pub fn encode_string(s: &str) -> Vec<u8> {
    encode_octet_string(s.as_bytes())
}

pub fn encode_set(items: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flatten().copied().collect();
    encode_tlv(TAG_SET, &content)
}

// Decoding

/// Parse a TLV from the start of `buf`.
/// Returns `(tag, value_slice, remaining_slice)`.
pub fn parse_tlv(buf: &[u8]) -> BerResult<(u8, &[u8], &[u8])> {
    if buf.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let tag = buf[0];
    if tag & 0x1f == 0x1f {
        return Err(BerError::LongFormTag);
    }
    let (len, len_sz) = decode_length(&buf[1..])?;
    let value_start = 1 + len_sz;
    if buf.len() < value_start + len {
        return Err(BerError::UnexpectedEof);
    }
    Ok((tag, &buf[value_start..value_start + len], &buf[value_start + len..]))
}

/// Decode a BER length field from `buf`.
///
/// BER uses two forms:
/// - **Short form** (`buf[0]` bit 7 clear): the length is the byte value itself.
/// - **Long form** (`buf[0]` bit 7 set): the low 7 bits give the number of
///   following bytes that encode the length in big-endian order.
///
/// Returns `(length, bytes_consumed)`.
pub fn decode_length(buf: &[u8]) -> BerResult<(usize, usize)> {
    if buf.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    if buf[0] & 0x80 == 0 {
        return Ok((buf[0] as usize, 1));
    }
    let n = (buf[0] & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(BerError::LengthOutOfRange);
    }
    if buf.len() < 1 + n {
        return Err(BerError::UnexpectedEof);
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | buf[1 + i] as usize;
    }
    Ok((len, 1 + n))
}

pub fn expect_tag(
    buf: &[u8],
    expected: u8,
) -> BerResult<(&[u8], &[u8])> {
    let (tag, value, rest) = parse_tlv(buf)?;
    if tag != expected {
        return Err(BerError::UnexpectedTag { expected, got: tag });
    }
    Ok((value, rest))
}

/// Decode a BER INTEGER into an `i64`.
///
/// BER integers are big-endian two's-complement with no redundant leading
/// bytes. The sign is determined by the high bit of the first content byte;
/// we initialise the accumulator to `0` or `-1` so that sign-extension
/// happens naturally as we shift in subsequent bytes.
pub fn decode_integer(buf: &[u8]) -> BerResult<(i64, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_INTEGER)?;
    Ok((decode_integer_bytes(value)?, rest))
}

/// Decode the content octets of a BER INTEGER. Shared with callers that
/// carry an integer under a non-universal tag (e.g. AbandonRequest).
/// Values wider than 8 octets cannot be represented and are rejected
/// rather than silently truncated.
pub fn decode_integer_bytes(value: &[u8]) -> BerResult<i64> {
    if value.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    if value.len() > 8 {
        return Err(BerError::LengthOutOfRange);
    }
    let mut n = if value[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for b in value {
        n = (n << 8) | *b as i64;
    }
    Ok(n)
}

/// Decode a BER ENUMERATED into a `u32`. Negative values and values above
/// `u32::MAX` have no meaning for LDAP enumerations and are rejected.
pub fn decode_enumerated(buf: &[u8]) -> BerResult<(u32, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_ENUMERATED)?;
    let n = decode_integer_bytes(value)?;
    let n = u32::try_from(n).map_err(|_| BerError::InvalidValue)?;
    Ok((n, rest))
}

pub fn decode_octet_string(buf: &[u8]) -> BerResult<(Vec<u8>, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_OCTET_STRING)?;
    Ok((value.to_vec(), rest))
}

pub fn decode_string(buf: &[u8]) -> BerResult<(String, &[u8])> {
    let (bytes, rest) = decode_octet_string(buf)?;
    let s = String::from_utf8(bytes).map_err(|_| BerError::InvalidUtf8)?;
    Ok((s, rest))
}

pub fn decode_boolean(buf: &[u8]) -> BerResult<(bool, &[u8])> {
    let (value, rest) = expect_tag(buf, TAG_BOOLEAN)?;
    Ok((!value.is_empty() && value[0] != 0, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integer

    #[test]
    fn integer_roundtrip() {
        for n in [
            0i64, 1, 127, 128, 255, 256, 32767, 32768,
            -1, -128, -129, i32::MAX as i64,
        ] {
            let enc = encode_integer(n);
            let (dec, rest) = decode_integer(&enc).unwrap();
            assert_eq!(dec, n, "roundtrip failed for {n}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn integer_known_encodings() {
        // Single-byte values
        assert_eq!(encode_integer(0), &[0x02, 0x01, 0x00]);
        assert_eq!(encode_integer(1), &[0x02, 0x01, 0x01]);
        assert_eq!(encode_integer(127), &[0x02, 0x01, 0x7f]);
        // Two bytes needed when high bit of first byte would be set
        assert_eq!(encode_integer(128), &[0x02, 0x02, 0x00, 0x80]);
        // Negative
        assert_eq!(encode_integer(-1), &[0x02, 0x01, 0xff]);
        assert_eq!(encode_integer(-128), &[0x02, 0x01, 0x80]);
    }

    #[test]
    fn integer_too_wide_rejected() {
        let buf = [0x02, 0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            decode_integer(&buf),
            Err(BerError::LengthOutOfRange)
        ));
        // Eight octets is the widest accepted value.
        let buf = [0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode_integer(&buf).unwrap().0, i64::MAX);
    }

    #[test]
    fn integer_empty_rejected() {
        assert!(decode_integer(&[0x02, 0x00]).is_err());
    }

    // Enumerated

    #[test]
    fn enumerated_range_checks() {
        // Above u32::MAX.
        let buf = [0x0a, 0x05, 0x01, 0, 0, 0, 0];
        assert!(matches!(decode_enumerated(&buf), Err(BerError::InvalidValue)));
        // Negative.
        let buf = [0x0a, 0x01, 0xff];
        assert!(matches!(decode_enumerated(&buf), Err(BerError::InvalidValue)));
        // Over-wide.
        let buf = [0x0a, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(matches!(decode_enumerated(&buf), Err(BerError::LengthOutOfRange)));
        // u32::MAX needs a leading zero octet to stay positive.
        let enc = encode_enumerated(u32::MAX);
        assert_eq!(enc, &[0x0a, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(decode_enumerated(&enc).unwrap().0, u32::MAX);
        assert!(decode_enumerated(&[0x0a, 0x00]).is_err());
    }

    #[test]
    fn enumerated_roundtrip() {
        for n in [0u32, 1, 49, 80, 127, 128, 255, 256, 1 << 24, 1 << 31, u32::MAX] {
            let enc = encode_enumerated(n);
            let (dec, rest) = decode_enumerated(&enc).unwrap();
            assert_eq!(dec, n);
            assert!(rest.is_empty());
        }
    }

    // Octet string

    #[test]
    fn string_roundtrip() {
        for s in ["", "hello", "uid=alice,ou=people,dc=example,dc=com"] {
            let enc = encode_string(s);
            let (dec, rest) = decode_string(&enc).unwrap();
            assert_eq!(dec, s);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn empty_string_encoding() {
        assert_eq!(encode_string(""), &[0x04, 0x00]);
    }

    // Length encoding

    #[test]
    fn length_short_form() {
        assert_eq!(encode_length(0), &[0x00]);
        assert_eq!(encode_length(1), &[0x01]);
        assert_eq!(encode_length(127), &[0x7f]);
    }

    #[test]
    fn length_long_form() {
        assert_eq!(encode_length(128), &[0x81, 0x80]);
        assert_eq!(encode_length(255), &[0x81, 0xff]);
        assert_eq!(encode_length(256), &[0x82, 0x01, 0x00]);
        assert_eq!(encode_length(65535), &[0x82, 0xff, 0xff]);
    }

    #[test]
    fn length_four_byte_form() {
        assert_eq!(encode_length(0x1000000), &[0x84, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn length_roundtrip() {
        for len in [
            0usize, 1, 127, 128, 255, 256, 1000, 65535, 0x10000, 0xffffff,
            0x1000000, 0x7fffffff,
        ] {
            let enc = encode_length(len);
            let (dec, consumed) = decode_length(&enc).unwrap();
            assert_eq!(dec, len);
            assert_eq!(consumed, enc.len());
        }
    }

    // TLV

    #[test]
    fn parse_tlv_basic() {
        // OCTET STRING "abc" + trailing garbage
        let buf = [0x04, 0x03, b'a', b'b', b'c', 0xff];
        let (tag, value, rest) = parse_tlv(&buf).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(value, b"abc");
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn parse_tlv_empty_value() {
        let buf = [0x04, 0x00];
        let (tag, value, rest) = parse_tlv(&buf).unwrap();
        assert_eq!(tag, 0x04);
        assert!(value.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_length_rejects_indefinite_and_wide_forms() {
        // 0x80 is the indefinite form, not permitted in LDAP.
        assert!(decode_length(&[0x80]).is_err());
        // Five length octets exceed the supported range.
        assert!(decode_length(&[0x85, 0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn parse_tlv_unexpected_eof() {
        assert!(parse_tlv(&[]).is_err());
        // says 3 bytes, only 2 present
        assert!(parse_tlv(&[0x04, 0x03, b'a', b'b']).is_err());
    }

    // Boolean

    #[test]
    fn boolean_true() {
        let buf = [0x01, 0x01, 0xff];
        let (v, rest) = decode_boolean(&buf).unwrap();
        assert!(v);
        assert!(rest.is_empty());
    }

    #[test]
    fn boolean_false() {
        let buf = [0x01, 0x01, 0x00];
        let (v, rest) = decode_boolean(&buf).unwrap();
        assert!(!v);
        assert!(rest.is_empty());
    }


    #[test]
    fn boolean_empty_content_is_false() {
        let (v, _) = decode_boolean(&[0x01, 0x00]).unwrap();
        assert!(!v);
    }

    #[test]
    fn expect_tag_mismatch_reports_both_tags() {
        let err = expect_tag(&[0x04, 0x00], TAG_INTEGER).unwrap_err();
        assert!(matches!(err, BerError::UnexpectedTag { expected: 0x02, got: 0x04 }));
        assert_eq!(err.to_string(), "Unexpected tag: expected 0x02, got 0x04");
    }

    #[test]
    fn long_form_tags_are_rejected() {
        assert!(matches!(parse_tlv(&[0x1f, 0x00]), Err(BerError::LongFormTag)));
        assert!(matches!(parse_tlv(&[0xbf, 0x00]), Err(BerError::LongFormTag)));
    }

    #[test]
    fn decode_string_rejects_bad_utf8() {
        assert!(matches!(decode_string(&[0x04, 0x01, 0xff]), Err(BerError::InvalidUtf8)));
    }

    #[test]
    fn error_display_strings_are_distinct() {
        let errs = [
            BerError::UnexpectedEof,
            BerError::LongFormTag,
            BerError::UnexpectedTag { expected: 1, got: 2 },
            BerError::InvalidUtf8,
            BerError::LengthOutOfRange,
            BerError::NestingTooDeep,
            BerError::InvalidValue,
        ];
        let texts: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
        for (i, a) in texts.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &texts[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // It is a std Error too.
        let _: &dyn std::error::Error = &errs[0];
    }

    #[test]
    fn encode_set_concatenates_items() {
        let set = encode_set(&[encode_string("a"), encode_string("b")]);
        assert_eq!(set, &[0x31, 0x06, 0x04, 0x01, b'a', 0x04, 0x01, b'b']);
    }

    // Remaining bytes

    #[test]
    fn decode_leaves_remainder() {
        // Two integers concatenated
        let mut buf = encode_integer(42);
        buf.extend(encode_integer(99));
        let (first, rest) = decode_integer(&buf).unwrap();
        let (second, rest2) = decode_integer(rest).unwrap();
        assert_eq!(first, 42);
        assert_eq!(second, 99);
        assert!(rest2.is_empty());
    }
}
