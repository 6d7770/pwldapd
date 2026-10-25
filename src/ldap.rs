/// LDAP protocol types, parser, encoder, and filter evaluator.
use crate::ber::{self, BerError, BerResult};
use std::cmp::Ordering;
use zeroize::Zeroizing;

// Result codes
pub const SUCCESS: u32 = 0;
pub const PROTOCOL_ERROR: u32 = 2;
pub const SIZE_LIMIT_EXCEEDED: u32 = 4;
pub const AUTH_METHOD_NOT_SUPPORTED: u32 = 7;
pub const INVALID_CREDENTIALS: u32 = 49;
pub const INSUFFICIENT_ACCESS_RIGHTS: u32 = 50;
pub const UNWILLING_TO_PERFORM: u32 = 53;

/// OID carried in the Notice of Disconnection (RFC 4511 section 4.4.1).
pub const NOTICE_OF_DISCONNECTION_OID: &str = "1.3.6.1.4.1.1466.20036";

// Application tags
const APP_BIND_REQUEST: u8 = 0x60;
const APP_BIND_RESPONSE: u8 = 0x61;
const APP_UNBIND_REQUEST: u8 = 0x42;
const APP_SEARCH_REQUEST: u8 = 0x63;
const APP_SEARCH_RESULT_ENTRY: u8 = 0x64;
const APP_SEARCH_RESULT_DONE: u8 = 0x65;
const APP_MODIFY_REQUEST: u8 = 0x66;
const APP_ADD_REQUEST: u8 = 0x68;
const APP_DEL_REQUEST: u8 = 0x4a;
const APP_MODIFY_DN_REQUEST: u8 = 0x6c;
const APP_COMPARE_REQUEST: u8 = 0x6e;
const APP_ABANDON_REQUEST: u8 = 0x70;
const APP_EXTENDED_REQUEST: u8 = 0x77;
const APP_EXTENDED_RESPONSE: u8 = 0x78;

// simple auth is context [0] primitive
const CTX_SIMPLE_AUTH: u8 = 0x80;
// ExtendedResponse.responseName is context [10] primitive
const CTX_RESPONSE_NAME: u8 = 0x8a;

/// Attribute list as carried in a search result entry.
pub type Attrs = Vec<(String, Vec<String>)>;

// Types

#[derive(Debug, Clone)]
pub struct LdapMessage {
    pub message_id: i64,
    pub operation: LdapOperation,
}

/// A client request. Operations the server does not implement are parsed
/// only as far as their tag so that a well-formed refusal can be sent.
#[derive(Debug, Clone)]
pub enum LdapOperation {
    BindRequest(BindRequest),
    UnbindRequest,
    SearchRequest(SearchRequest),
    AbandonRequest(i64),
    /// A syntactically recognised request this server does not implement.
    /// `response_tag` is the application tag of the matching response.
    Unsupported { tag: u8, response_tag: u8 },
}

/// A server response, encoded with `encode_response`.
#[derive(Debug, Clone)]
pub enum Response {
    Bind(LdapResult),
    SearchEntry(SearchResultEntry),
    SearchDone(LdapResult),
    Extended { result: LdapResult, name: Option<String> },
    /// Result-only response for an unsupported request type.
    Generic { tag: u8, result: LdapResult },
}

#[derive(Debug, Clone)]
pub struct LdapResult {
    pub result_code: u32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

impl LdapResult {
    pub fn success() -> Self {
        Self {
            result_code: SUCCESS,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
        }
    }
    pub fn error(code: u32, msg: impl Into<String>) -> Self {
        Self {
            result_code: code,
            matched_dn: String::new(),
            diagnostic_message: msg.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BindAuth {
    Simple(Zeroizing<String>),
    /// SASL or any other authentication choice; never accepted.
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub name: String,
    pub auth: BindAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base = 0,
    OneLevel = 1,
    WholeSubtree = 2,
}

#[derive(Debug, Clone)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch { attr: String, value: String },
    Substrings {
        attr: String,
        initial: Option<String>,
        any: Vec<String>,
        final_: Option<String>,
    },
    GreaterOrEqual { attr: String, value: String },
    LessOrEqual { attr: String, value: String },
    Present(String),
    ApproxMatch,
    /// A filter choice this server cannot evaluate (e.g. extensibleMatch).
    /// Evaluates to Undefined, which RFC 4511 treats as a non-match.
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub base_dn: String,
    pub scope: Scope,
    /// Maximum entries to return; 0 means no client-imposed limit.
    pub size_limit: i64,
    /// Return attribute names only, with empty value sets.
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub dn: String,
    pub attributes: Attrs,
}

// DN handling

/// Normalise a DN for comparison: strip whitespace around each RDN and
/// lowercase the whole string. The attribute types used in this directory
/// (uid, cn, ou, dc) all use case-insensitive matching rules, so lowercasing
/// values is correct here. Escaped commas (`\,`) do not split RDNs.
pub fn normalize_dn(dn: &str) -> String {
    split_rdns(dn)
        .into_iter()
        .map(|rdn| rdn.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// Split a DN into its RDN strings on unescaped commas.
pub fn split_rdns(dn: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in dn.char_indices() {
        match c {
            '\\' => escaped = !escaped,
            ',' if !escaped => {
                parts.push(&dn[start..i]);
                start = i + 1;
            }
            _ => escaped = false,
        }
    }
    parts.push(&dn[start..]);
    parts
}

/// If `dn` is `<attr>=<value>,<parent>` where `attr` matches `attr_type`
/// case-insensitively and `parent` normalises to `parent_norm`, return
/// `value` with surrounding whitespace removed but case preserved.
pub fn leaf_value<'a>(
    dn: &'a str,
    attr_type: &str,
    parent_norm: &str,
) -> Option<&'a str> {
    let rdns = split_rdns(dn);
    let (first, parent) = rdns.split_first()?;
    let (attr, value) = first.split_once('=')?;
    if !attr.trim().eq_ignore_ascii_case(attr_type) {
        return None;
    }
    let value = value.trim();
    if value.is_empty() || normalize_dn(&parent.join(",")) != parent_norm {
        return None;
    }
    Some(value)
}

// Parsing

/// Parse a complete LDAP message from a BER-encoded buffer.
/// The buffer must contain exactly one top-level SEQUENCE with a message ID
/// followed by a protocol operation. Trailing bytes (controls) are ignored.
pub fn parse_message(buf: &[u8]) -> BerResult<LdapMessage> {
    let (seq, _) = ber::expect_tag(buf, ber::TAG_SEQUENCE)?;
    let (message_id, rest) = ber::decode_integer(seq)?;
    let (op_tag, op_value, _) = ber::parse_tlv(rest)?;

    let operation = match op_tag {
        APP_BIND_REQUEST => LdapOperation::BindRequest(
            parse_bind_request(op_value)?,
        ),
        APP_UNBIND_REQUEST => LdapOperation::UnbindRequest,
        APP_SEARCH_REQUEST => LdapOperation::SearchRequest(
            parse_search_request(op_value)?,
        ),
        APP_ABANDON_REQUEST => LdapOperation::AbandonRequest(
            ber::decode_integer_bytes(op_value)?,
        ),
        APP_MODIFY_REQUEST
        | APP_ADD_REQUEST
        | APP_DEL_REQUEST
        | APP_MODIFY_DN_REQUEST
        | APP_COMPARE_REQUEST => LdapOperation::Unsupported {
            tag: op_tag,
            response_tag: op_tag + 1,
        },
        APP_EXTENDED_REQUEST => LdapOperation::Unsupported {
            tag: op_tag,
            response_tag: APP_EXTENDED_RESPONSE,
        },
        tag => {
            tracing::warn!("Unknown LDAP operation tag {tag:#04x}");
            return Err(BerError::UnexpectedTag { expected: 0, got: tag });
        }
    };

    Ok(LdapMessage { message_id, operation })
}

fn parse_bind_request(buf: &[u8]) -> BerResult<BindRequest> {
    let (_, rest) = ber::decode_integer(buf)?; // version: not used
    let (name, rest) = ber::decode_string(rest)?;
    let (auth_tag, auth_value, _) = ber::parse_tlv(rest)?;
    let auth = match auth_tag {
        CTX_SIMPLE_AUTH => {
            let pw = Zeroizing::new(
                String::from_utf8(auth_value.to_vec())
                    .map_err(|_| BerError::InvalidUtf8)?,
            );
            BindAuth::Simple(pw)
        }
        _ => BindAuth::Unsupported,
    };
    Ok(BindRequest { name, auth })
}

fn parse_search_request(buf: &[u8]) -> BerResult<SearchRequest> {
    let (base_dn, rest) = ber::decode_string(buf)?;
    let (scope_val, rest) = ber::decode_enumerated(rest)?;
    let (_, rest) = ber::decode_enumerated(rest)?; // derefAliases: not used
    let (size_limit, rest) = ber::decode_integer(rest)?;
    let (_, rest) = ber::decode_integer(rest)?;    // timeLimit: not used
    let (types_only, rest) = ber::decode_boolean(rest)?;
    let (filter, rest) = parse_filter(rest, 0)?;

    let mut attributes = Vec::new();
    if !rest.is_empty() {
        let (attrs_seq, _) = ber::expect_tag(rest, ber::TAG_SEQUENCE)?;
        let mut r = attrs_seq;
        while !r.is_empty() {
            let (attr, next) = ber::decode_string(r)?;
            attributes.push(attr);
            r = next;
        }
    }

    let scope = match scope_val {
        0 => Scope::Base,
        1 => Scope::OneLevel,
        2 => Scope::WholeSubtree,
        _ => return Err(BerError::InvalidValue),
    };

    Ok(SearchRequest {
        base_dn,
        scope,
        size_limit: size_limit.max(0),
        types_only,
        filter,
        attributes,
    })
}

const MAX_FILTER_DEPTH: u32 = 32;

fn parse_filter(buf: &[u8], depth: u32) -> BerResult<(Filter, &[u8])> {
    if depth > MAX_FILTER_DEPTH {
        return Err(BerError::NestingTooDeep);
    }
    let (tag, value, rest) = ber::parse_tlv(buf)?;

    let filter = match tag {
        0xa0 => Filter::And(parse_filter_list(value, depth + 1)?),
        0xa1 => Filter::Or(parse_filter_list(value, depth + 1)?),
        0xa2 => {
            let (inner, _) = parse_filter(value, depth + 1)?;
            Filter::Not(Box::new(inner))
        }
        0xa3 => {
            let (attr, value) = parse_ava(value)?;
            Filter::EqualityMatch { attr, value }
        }
        0xa4 => parse_substrings(value)?,
        0xa5 => {
            let (attr, value) = parse_ava(value)?;
            Filter::GreaterOrEqual { attr, value }
        }
        0xa6 => {
            let (attr, value) = parse_ava(value)?;
            Filter::LessOrEqual { attr, value }
        }
        0x87 => {
            let attr = String::from_utf8(value.to_vec())
                .map_err(|_| BerError::InvalidUtf8)?;
            Filter::Present(attr)
        }
        0xa8 => Filter::ApproxMatch,
        // Any other context tag (e.g. 0xa9 extensibleMatch) is a legal
        // filter we cannot evaluate. Its TLV is already consumed, so the
        // rest of the request still parses.
        _ => {
            tracing::debug!("Unsupported filter tag {tag:#04x}");
            Filter::Unsupported
        }
    };
    Ok((filter, rest))
}

/// Parse an AttributeValueAssertion: SEQUENCE { attr, value }.
fn parse_ava(buf: &[u8]) -> BerResult<(String, String)> {
    let (attr, v) = ber::decode_string(buf)?;
    let (val, _) = ber::decode_string(v)?;
    Ok((attr, val))
}

fn parse_filter_list(buf: &[u8], depth: u32) -> BerResult<Vec<Filter>> {
    let mut filters = Vec::new();
    let mut r = buf;
    while !r.is_empty() {
        let (f, next) = parse_filter(r, depth)?;
        filters.push(f);
        r = next;
    }
    Ok(filters)
}

fn parse_substrings(buf: &[u8]) -> BerResult<Filter> {
    let (attr, rest) = ber::decode_string(buf)?;
    let (subs_seq, _) = ber::expect_tag(rest, ber::TAG_SEQUENCE)?;
    let mut initial = None;
    let mut any = Vec::new();
    let mut final_ = None;
    let mut r = subs_seq;
    while !r.is_empty() {
        let (sub_tag, sub_val, next) = ber::parse_tlv(r)?;
        let s = String::from_utf8(sub_val.to_vec())
            .map_err(|_| BerError::InvalidUtf8)?;
        match sub_tag {
            0x80 => initial = Some(s),
            0x81 => any.push(s),
            0x82 => final_ = Some(s),
            _ => {}
        }
        r = next;
    }
    Ok(Filter::Substrings { attr, initial, any, final_ })
}

// Encoding

/// Encode a response as a BER LDAPMessage SEQUENCE.
pub fn encode_response(message_id: i64, resp: &Response) -> Vec<u8> {
    let mut content = ber::encode_integer(message_id);
    content.extend(match resp {
        Response::Bind(r) => encode_ldap_result(APP_BIND_RESPONSE, r),
        Response::SearchEntry(e) => encode_search_result_entry(e),
        Response::SearchDone(r) => {
            encode_ldap_result(APP_SEARCH_RESULT_DONE, r)
        }
        Response::Extended { result, name } => {
            let mut body = ldap_result_content(result);
            if let Some(n) = name {
                body.extend(ber::encode_tlv(CTX_RESPONSE_NAME, n.as_bytes()));
            }
            ber::encode_tlv(APP_EXTENDED_RESPONSE, &body)
        }
        Response::Generic { tag, result } => encode_ldap_result(*tag, result),
    });
    ber::encode_tlv(ber::TAG_SEQUENCE, &content)
}

/// Unsolicited Notice of Disconnection (RFC 4511 section 4.4.1), sent with
/// message ID 0 before the server closes a connection on malformed input.
pub fn notice_of_disconnection(msg: &str) -> Vec<u8> {
    encode_response(0, &Response::Extended {
        result: LdapResult::error(PROTOCOL_ERROR, msg),
        name: Some(NOTICE_OF_DISCONNECTION_OID.to_string()),
    })
}

fn ldap_result_content(r: &LdapResult) -> Vec<u8> {
    let mut content = ber::encode_enumerated(r.result_code);
    content.extend(ber::encode_string(&r.matched_dn));
    content.extend(ber::encode_string(&r.diagnostic_message));
    content
}

fn encode_ldap_result(tag: u8, r: &LdapResult) -> Vec<u8> {
    ber::encode_tlv(tag, &ldap_result_content(r))
}

fn encode_search_result_entry(entry: &SearchResultEntry) -> Vec<u8> {
    let mut content = ber::encode_string(&entry.dn);
    let mut attrs_content = Vec::new();
    for (name, values) in &entry.attributes {
        let vals: Vec<Vec<u8>> = values
            .iter()
            .map(|v| ber::encode_string(v))
            .collect();
        let mut attr_seq = ber::encode_string(name);
        attr_seq.extend(ber::encode_set(&vals));
        attrs_content.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &attr_seq));
    }
    content.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &attrs_content));
    ber::encode_tlv(APP_SEARCH_RESULT_ENTRY, &content)
}

// Filter evaluation

/// Values of the attribute named `attr` (case-insensitive), if present.
fn attr_values<'a>(attrs: &'a Attrs, attr: &str) -> Option<&'a [String]> {
    attrs
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(attr))
        .map(|(_, vals)| vals.as_slice())
}

/// Compare two attribute values for ordering filters. Both sides numeric
/// means integer comparison (uidNumber, gidNumber); otherwise a
/// case-insensitive string comparison.
fn compare_values(a: &str, b: &str) -> Ordering {
    match (a.trim().parse::<i64>(), b.trim().parse::<i64>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        _ => a.to_lowercase().cmp(&b.to_lowercase()),
    }
}

/// Evaluate a parsed LDAP filter against a set of entry attributes.
/// All string comparisons are case-insensitive. `objectClass` is treated
/// as always present regardless of the stored attribute list.
pub fn matches_filter(filter: &Filter, attrs: &Attrs) -> bool {
    match filter {
        Filter::Present(attr) => {
            attr.eq_ignore_ascii_case("objectclass")
                || attr_values(attrs, attr).is_some()
        }
        Filter::EqualityMatch { attr, value } => {
            let vl = value.to_lowercase();
            attr_values(attrs, attr).is_some_and(|vals| {
                vals.iter().any(|v| v.to_lowercase() == vl)
            })
        }
        Filter::GreaterOrEqual { attr, value } => {
            attr_values(attrs, attr).is_some_and(|vals| {
                vals.iter().any(|v| compare_values(v, value) != Ordering::Less)
            })
        }
        Filter::LessOrEqual { attr, value } => {
            attr_values(attrs, attr).is_some_and(|vals| {
                vals.iter()
                    .any(|v| compare_values(v, value) != Ordering::Greater)
            })
        }
        Filter::And(filters) =>
            filters.iter().all(|f| matches_filter(f, attrs)),
        Filter::Or(filters) =>
            filters.iter().any(|f| matches_filter(f, attrs)),
        Filter::Not(f) => !matches_filter(f, attrs),
        Filter::Substrings { attr, initial, any, final_ } => {
            attr_values(attrs, attr).is_some_and(|vals| {
                vals.iter().any(|v| {
                    matches_substrings(&v.to_lowercase(), initial, any, final_)
                })
            })
        }
        // Approx match is implementation-defined; unsupported filters are
        // Undefined. Neither selects an entry.
        Filter::ApproxMatch | Filter::Unsupported => false,
    }
}

/// Match `vl` (already lowercased) against the substring components.
/// Each component is consumed left to right so that the pieces cannot
/// overlap.
fn matches_substrings(
    vl: &str,
    initial: &Option<String>,
    any: &[String],
    final_: &Option<String>,
) -> bool {
    let mut rem = vl;
    if let Some(i) = initial {
        let il = i.to_lowercase();
        match rem.strip_prefix(il.as_str()) {
            Some(r) => rem = r,
            None => return false,
        }
    }
    for sub in any {
        let sl = sub.to_lowercase();
        match rem.find(&sl) {
            Some(pos) => rem = &rem[pos + sl.len()..],
            None => return false,
        }
    }
    match final_ {
        Some(fin) => rem.ends_with(&fin.to_lowercase()),
        None => true,
    }
}

/// BER builders and decoders shared by the test modules of this crate.
#[cfg(test)]
pub mod testutil {
    use super::*;
    use crate::ber;

    /// Wrap a BER-encoded protocol op in an LDAPMessage with `id`.
    pub fn envelope(id: i64, op: Vec<u8>) -> Vec<u8> {
        let mut content = ber::encode_integer(id);
        content.extend(op);
        ber::encode_tlv(ber::TAG_SEQUENCE, &content)
    }

    /// Simple bind: version 3, `name`, `password` under the [0] choice.
    pub fn bind_msg(id: i64, name: &str, password: &str) -> Vec<u8> {
        let mut body = ber::encode_integer(3);
        body.extend(ber::encode_string(name));
        body.extend(ber::encode_tlv(CTX_SIMPLE_AUTH, password.as_bytes()));
        envelope(id, ber::encode_tlv(APP_BIND_REQUEST, &body))
    }

    /// SASL bind with the given mechanism and no credentials.
    pub fn sasl_bind_msg(id: i64, mechanism: &str) -> Vec<u8> {
        let mut body = ber::encode_integer(3);
        body.extend(ber::encode_string(""));
        body.extend(ber::encode_tlv(0xa3, &ber::encode_string(mechanism)));
        envelope(id, ber::encode_tlv(APP_BIND_REQUEST, &body))
    }

    pub fn unbind_msg(id: i64) -> Vec<u8> {
        envelope(id, ber::encode_tlv(APP_UNBIND_REQUEST, &[]))
    }

    /// Search request with the given raw filter bytes and no attribute list
    /// restriction.
    pub fn search_msg(
        id: i64,
        base: &str,
        scope: u32,
        size_limit: i64,
        types_only: bool,
        filter: Vec<u8>,
    ) -> Vec<u8> {
        search_msg_attrs(id, base, scope, size_limit, types_only, filter, &[])
    }

    pub fn search_msg_attrs(
        id: i64,
        base: &str,
        scope: u32,
        size_limit: i64,
        types_only: bool,
        filter: Vec<u8>,
        attrs: &[&str],
    ) -> Vec<u8> {
        let mut body = ber::encode_string(base);
        body.extend(ber::encode_enumerated(scope));
        body.extend(ber::encode_enumerated(0));
        body.extend(ber::encode_integer(size_limit));
        body.extend(ber::encode_integer(0));
        body.extend(ber::encode_tlv(
            ber::TAG_BOOLEAN,
            &[if types_only { 0xff } else { 0 }],
        ));
        body.extend(filter);
        let attr_list: Vec<u8> =
            attrs.iter().flat_map(|a| ber::encode_string(a)).collect();
        body.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &attr_list));
        envelope(id, ber::encode_tlv(APP_SEARCH_REQUEST, &body))
    }

    /// Filter builders (raw BER).
    pub fn f_present(attr: &str) -> Vec<u8> {
        ber::encode_tlv(0x87, attr.as_bytes())
    }
    fn ava(tag: u8, attr: &str, value: &str) -> Vec<u8> {
        let mut c = ber::encode_string(attr);
        c.extend(ber::encode_string(value));
        ber::encode_tlv(tag, &c)
    }
    pub fn f_eq(attr: &str, value: &str) -> Vec<u8> { ava(0xa3, attr, value) }
    pub fn f_ge(attr: &str, value: &str) -> Vec<u8> { ava(0xa5, attr, value) }
    pub fn f_le(attr: &str, value: &str) -> Vec<u8> { ava(0xa6, attr, value) }
    pub fn f_and(parts: &[Vec<u8>]) -> Vec<u8> {
        ber::encode_tlv(0xa0, &parts.concat())
    }
    pub fn f_or(parts: &[Vec<u8>]) -> Vec<u8> {
        ber::encode_tlv(0xa1, &parts.concat())
    }
    pub fn f_not(inner: Vec<u8>) -> Vec<u8> {
        ber::encode_tlv(0xa2, &inner)
    }
    /// Substring filter from optional initial, any list and optional final.
    pub fn f_substrings(
        attr: &str,
        initial: Option<&str>,
        any: &[&str],
        final_: Option<&str>,
    ) -> Vec<u8> {
        let mut subs = Vec::new();
        if let Some(i) = initial {
            subs.extend(ber::encode_tlv(0x80, i.as_bytes()));
        }
        for a in any {
            subs.extend(ber::encode_tlv(0x81, a.as_bytes()));
        }
        if let Some(f) = final_ {
            subs.extend(ber::encode_tlv(0x82, f.as_bytes()));
        }
        let mut c = ber::encode_string(attr);
        c.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &subs));
        ber::encode_tlv(0xa4, &c)
    }

    /// Decode `(message_id, op_tag, op_value)` from one encoded message.
    pub fn decode_envelope(bytes: &[u8]) -> (i64, u8, Vec<u8>) {
        let (seq, rest) = ber::expect_tag(bytes, ber::TAG_SEQUENCE).unwrap();
        assert!(rest.is_empty(), "trailing bytes after message");
        let (id, rest) = ber::decode_integer(seq).unwrap();
        let (tag, value, _) = ber::parse_tlv(rest).unwrap();
        (id, tag, value.to_vec())
    }

    /// Result code from an LDAPResult-shaped op value.
    pub fn result_code(op_value: &[u8]) -> u32 {
        ber::decode_enumerated(op_value).unwrap().0
    }

    /// Response application tags.
    pub const BIND_RESPONSE: u8 = APP_BIND_RESPONSE;
    pub const SEARCH_RESULT_ENTRY: u8 = APP_SEARCH_RESULT_ENTRY;
    pub const SEARCH_RESULT_DONE: u8 = APP_SEARCH_RESULT_DONE;
    pub const EXTENDED_RESPONSE: u8 = APP_EXTENDED_RESPONSE;
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::ber;
    use proptest::prelude::*;

    // Helpers

    fn attrs(pairs: &[(&str, &[&str])]) -> Attrs {
        pairs
            .iter()
            .map(|(k, vs)| {
                (k.to_string(), vs.iter().map(|v| v.to_string()).collect())
            })
            .collect()
    }

    fn eq(attr: &str, value: &str) -> Filter {
        Filter::EqualityMatch { attr: attr.into(), value: value.into() }
    }

    fn ge(attr: &str, value: &str) -> Filter {
        Filter::GreaterOrEqual { attr: attr.into(), value: value.into() }
    }

    fn le(attr: &str, value: &str) -> Filter {
        Filter::LessOrEqual { attr: attr.into(), value: value.into() }
    }

    // DN normalisation

    #[test]
    fn normalize_dn_strips_spaces_and_lowercases() {
        assert_eq!(
            normalize_dn("UID=Alice , ou=People, DC=Example,dc=com"),
            "uid=alice,ou=people,dc=example,dc=com"
        );
        assert_eq!(normalize_dn(""), "");
    }

    #[test]
    fn normalize_dn_keeps_escaped_commas() {
        assert_eq!(
            normalize_dn("cn=Smith\\, John,ou=people"),
            "cn=smith\\, john,ou=people"
        );
        assert_eq!(split_rdns("a=b\\,c,d=e"), vec!["a=b\\,c", "d=e"]);
    }

    #[test]
    fn leaf_value_matches_parent() {
        let parent = normalize_dn("ou=people,dc=example,dc=com");
        assert_eq!(
            leaf_value("uid=Alice, OU=People,dc=example,dc=com", "uid", &parent),
            Some("Alice")
        );
        assert_eq!(
            leaf_value("uid=alice,dc=evil", "uid", &parent),
            None
        );
        assert_eq!(
            leaf_value("cn=alice,ou=people,dc=example,dc=com", "uid", &parent),
            None
        );
        assert_eq!(leaf_value("alice", "uid", &parent), None);
        assert_eq!(
            leaf_value("uid=,ou=people,dc=example,dc=com", "uid", &parent),
            None
        );
    }

    // Filter: present

    #[test]
    fn filter_present_objectclass_always_matches() {
        // objectClass is synthetic: always present regardless of stored attrs
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&Filter::Present("objectClass".into()), &a));
        assert!(matches_filter(&Filter::Present("OBJECTCLASS".into()), &a));
    }

    #[test]
    fn filter_present_existing_attr() {
        let a = attrs(&[("uid", &["alice"]), ("cn", &["Alice Smith"])]);
        assert!(matches_filter(&Filter::Present("uid".into()), &a));
        assert!(matches_filter(&Filter::Present("cn".into()), &a));
    }

    #[test]
    fn filter_present_missing_attr() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&Filter::Present("mail".into()), &a));
    }

    // Filter: equality

    #[test]
    fn filter_equality_match() {
        let a = attrs(&[("uid", &["alice"]), ("cn", &["Alice Smith"])]);
        assert!(matches_filter(&eq("uid", "alice"), &a));
        assert!(!matches_filter(&eq("uid", "bob"), &a));
    }

    #[test]
    fn filter_equality_case_insensitive_attr_name() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&eq("UID", "alice"), &a));
        assert!(matches_filter(&eq("Uid", "alice"), &a));
    }

    #[test]
    fn filter_equality_case_insensitive_value() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&eq("uid", "Alice"), &a));
        assert!(matches_filter(&eq("uid", "ALICE"), &a));
    }

    #[test]
    fn filter_equality_multi_value_attr() {
        let a = attrs(&[("objectClass",
            &["top", "posixAccount", "inetOrgPerson"])]);
        assert!(matches_filter(&eq("objectClass", "posixAccount"), &a));
        assert!(matches_filter(&eq("objectClass", "top"), &a));
        assert!(!matches_filter(&eq("objectClass", "posixGroup"), &a));
    }

    // Filter: ordering

    #[test]
    fn filter_ordering_numeric() {
        let a = attrs(&[("uidNumber", &["1000"])]);
        assert!(matches_filter(&ge("uidNumber", "1000"), &a));
        assert!(matches_filter(&ge("uidNumber", "999"), &a));
        assert!(!matches_filter(&ge("uidNumber", "1001"), &a));
        assert!(matches_filter(&le("uidNumber", "1000"), &a));
        assert!(!matches_filter(&le("uidNumber", "999"), &a));
        // Numeric, not lexical: "1000" >= "200".
        assert!(matches_filter(&ge("uidNumber", "200"), &a));
    }

    #[test]
    fn filter_ordering_string_fallback() {
        let a = attrs(&[("cn", &["Bob"])]);
        assert!(matches_filter(&ge("cn", "alice"), &a));
        assert!(!matches_filter(&ge("cn", "carol"), &a));
        assert!(matches_filter(&le("cn", "carol"), &a));
    }

    #[test]
    fn filter_ordering_missing_attr_is_false() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&ge("uidNumber", "0"), &a));
        assert!(!matches_filter(&le("uidNumber", "99999"), &a));
    }

    // Filter: AND / OR / NOT

    #[test]
    fn filter_empty_and_is_vacuously_true() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&Filter::And(vec![]), &a));
    }

    #[test]
    fn filter_empty_or_is_vacuously_false() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&Filter::Or(vec![]), &a));
    }

    #[test]
    fn filter_unimplemented_always_false() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&Filter::ApproxMatch, &a));
        assert!(!matches_filter(&Filter::Unsupported, &a));
    }

    #[test]
    fn filter_and_both_match() {
        let a = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["alice"]),
        ]);
        let f = Filter::And(vec![
            eq("objectClass", "posixAccount"),
            eq("uid", "alice"),
        ]);
        assert!(matches_filter(&f, &a));
    }

    #[test]
    fn filter_and_one_fails() {
        let a = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["alice"]),
        ]);
        let f = Filter::And(vec![
            eq("objectClass", "posixAccount"),
            eq("uid", "bob"),
        ]);
        assert!(!matches_filter(&f, &a));
    }

    #[test]
    fn filter_or_one_matches() {
        let a = attrs(&[("uid", &["alice"])]);
        let f = Filter::Or(vec![eq("uid", "alice"), eq("uid", "bob")]);
        assert!(matches_filter(&f, &a));
    }

    #[test]
    fn filter_or_none_match() {
        let a = attrs(&[("uid", &["alice"])]);
        let f = Filter::Or(vec![eq("uid", "bob"), eq("uid", "carol")]);
        assert!(!matches_filter(&f, &a));
    }

    #[test]
    fn filter_not() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&Filter::Not(Box::new(eq("uid", "bob"))), &a));
        let not_alice = Filter::Not(Box::new(eq("uid", "alice")));
        assert!(!matches_filter(&not_alice, &a));
    }

    #[test]
    fn filter_nested_and_or() {
        // (&(objectClass=posixAccount)(|(uid=alice)(uid=bob)))
        let a = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["alice"]),
        ]);
        let f = Filter::And(vec![
            eq("objectClass", "posixAccount"),
            Filter::Or(vec![eq("uid", "alice"), eq("uid", "bob")]),
        ]);
        assert!(matches_filter(&f, &a));

        let b = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["carol"]),
        ]);
        assert!(!matches_filter(&f, &b));
    }

    // Filter: substrings

    fn subs(initial: Option<&str>, any: &[&str], final_: Option<&str>) -> Filter {
        Filter::Substrings {
            attr: "cn".into(),
            initial: initial.map(Into::into),
            any: any.iter().map(|s| s.to_string()).collect(),
            final_: final_.map(Into::into),
        }
    }

    #[test]
    fn filter_substring_initial() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        assert!(matches_filter(&subs(Some("Alice"), &[], None), &a));
        assert!(!matches_filter(&subs(Some("Bob"), &[], None), &a));
    }

    #[test]
    fn filter_substring_final() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        assert!(matches_filter(&subs(None, &[], Some("Smith")), &a));
        assert!(!matches_filter(&subs(None, &[], Some("Jones")), &a));
    }

    #[test]
    fn filter_substring_any() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        assert!(matches_filter(&subs(None, &["lic"], None), &a));
    }

    #[test]
    fn filter_substring_combined() {
        // (cn=Al*ce Sm*)
        let a = attrs(&[("cn", &["Alice Smith"])]);
        assert!(matches_filter(&subs(Some("Al"), &["ce Sm"], None), &a));
    }

    #[test]
    fn filter_substring_pieces_do_not_overlap() {
        // (cn=*aa*aa*) must not match "aaa".
        let a = attrs(&[("cn", &["aaa"])]);
        assert!(!matches_filter(&subs(None, &["aa", "aa"], None), &a));
        let b = attrs(&[("cn", &["aaaa"])]);
        assert!(matches_filter(&subs(None, &["aa", "aa"], None), &b));
    }

    #[test]
    fn filter_substring_case_insensitive() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        let f = Filter::Substrings {
            attr: "CN".into(),
            initial: Some("alice".into()),
            any: vec![],
            final_: None,
        };
        assert!(matches_filter(&f, &a));
    }

    // Message parsing: BindRequest

    // Anonymous bind: msgId=1, version=3, name="", simple=""
    // 30 0c 02 01 01 60 07 02 01 03 04 00 80 00
    const ANON_BIND: &[u8] = &[
        0x30, 0x0c,
          0x02, 0x01, 0x01,
          0x60, 0x07,
            0x02, 0x01, 0x03,
            0x04, 0x00,
            0x80, 0x00,
    ];

    #[test]
    fn parse_anonymous_bind_request() {
        let msg = parse_message(ANON_BIND).unwrap();
        assert_eq!(msg.message_id, 1);
        let LdapOperation::BindRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.name, "");
        let BindAuth::Simple(pw) = req.auth else { panic!("wrong auth") };
        assert_eq!(*pw, "");
    }

    // Authenticated bind: msgId=2, version=3,
    //   name="uid=alice,ou=people,dc=local", simple="secret"
    // Constructed by hand:
    //   name = "uid=alice,ou=people,dc=local" (28 bytes = 0x1c)
    //   password = "secret" (6 bytes)
    //   BindRequest content: 02 01 03  04 1c [name]  80 06 [pw]
    //     = 3+2+28+2+6 = 41 = 0x29
    //   msgId: 02 01 02 (3 bytes)
    //   Sequence content: 3 + 2 + 41 = 46 = 0x2e
    const AUTH_BIND: &[u8] = &[
        0x30, 0x2e,
          0x02, 0x01, 0x02,
          0x60, 0x29,
            0x02, 0x01, 0x03,
            0x04, 0x1c,
              b'u',b'i',b'd',b'=',b'a',b'l',b'i',b'c',b'e',b',',
              b'o',b'u',b'=',b'p',b'e',b'o',b'p',b'l',b'e',b',',
              b'd',b'c',b'=',b'l',b'o',b'c',b'a',b'l',
            0x80, 0x06,
              b's',b'e',b'c',b'r',b'e',b't',
    ];

    #[test]
    fn parse_authenticated_bind_request() {
        let msg = parse_message(AUTH_BIND).unwrap();
        assert_eq!(msg.message_id, 2);
        let LdapOperation::BindRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.name, "uid=alice,ou=people,dc=local");
        let BindAuth::Simple(pw) = req.auth else { panic!("wrong auth") };
        assert_eq!(*pw, "secret");
    }

    #[test]
    fn parse_sasl_bind_is_unsupported() {
        // sasl [3] SEQUENCE { mechanism "EXTERNAL" }
        let mut sasl = ber::encode_string("EXTERNAL");
        sasl = ber::encode_tlv(0xa3, &sasl);
        let mut body = ber::encode_integer(3);
        body.extend(ber::encode_string(""));
        body.extend(sasl);
        let msg = envelope(9, ber::encode_tlv(APP_BIND_REQUEST, &body));
        let msg = parse_message(&msg).unwrap();
        let LdapOperation::BindRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert!(matches!(req.auth, BindAuth::Unsupported));
    }

    // Message parsing: unsupported operations

    #[test]
    fn parse_unsupported_operations_yield_response_tags() {
        for (tag, want) in [
            (APP_MODIFY_REQUEST, 0x67),
            (APP_ADD_REQUEST, 0x69),
            (APP_DEL_REQUEST, 0x4b),
            (APP_MODIFY_DN_REQUEST, 0x6d),
            (APP_COMPARE_REQUEST, 0x6f),
            (APP_EXTENDED_REQUEST, APP_EXTENDED_RESPONSE),
        ] {
            let msg = envelope(5, ber::encode_tlv(tag, b"xx"));
            let msg = parse_message(&msg).unwrap();
            let LdapOperation::Unsupported { tag: t, response_tag } =
                msg.operation
                else { panic!("wrong op for {tag:#x}") };
            assert_eq!(t, tag);
            assert_eq!(response_tag, want);
        }
    }

    #[test]
    fn parse_unknown_operation_is_error() {
        let msg = envelope(5, ber::encode_tlv(0x7e, b""));
        assert!(parse_message(&msg).is_err());
    }

    #[test]
    fn parse_abandon_request() {
        let msg = envelope(6, ber::encode_tlv(APP_ABANDON_REQUEST, &[0x05]));
        let msg = parse_message(&msg).unwrap();
        assert!(matches!(msg.operation, LdapOperation::AbandonRequest(5)));
        // Over-wide id is rejected rather than truncated.
        let msg = envelope(6, ber::encode_tlv(APP_ABANDON_REQUEST, &[1; 9]));
        assert!(parse_message(&msg).is_err());
    }

    // Message parsing: SearchRequest

    // Search: msgId=3, base="ou=people,dc=local" (18 bytes=0x12),
    //   scope=subtree(2), deref=0, sizeLimit=0, timeLimit=0,
    //   typesOnly=false, filter=(uid=alice), attrs=[]
    //
    // filter (uid=alice): a3 0c  04 03 "uid"  04 05 "alice"  = 14 bytes
    // SearchReq content:
    //   04 12 [base]  0a 01 02  0a 01 00  02 01 00  02 01 00
    //   01 01 00  [filter]  30 00
    //   = 20 + 3 + 3 + 3 + 3 + 3 + 14 + 2 = 51 = 0x33
    // msgId: 02 01 03 (3)
    // Sequence content: 3 + 2 + 51 = 56 = 0x38
    const SEARCH_UID_ALICE: &[u8] = &[
        0x30, 0x38,
          0x02, 0x01, 0x03,
          0x63, 0x33,
            0x04, 0x12,
              b'o',b'u',b'=',b'p',b'e',b'o',b'p',b'l',b'e',b',',
              b'd',b'c',b'=',b'l',b'o',b'c',b'a',b'l',
            0x0a, 0x01, 0x02,  // scope = wholeSubtree
            0x0a, 0x01, 0x00,  // deref = neverDerefAliases
            0x02, 0x01, 0x00,  // sizeLimit = 0
            0x02, 0x01, 0x00,  // timeLimit = 0
            0x01, 0x01, 0x00,  // typesOnly = false
            0xa3, 0x0c,        // equalityMatch
              0x04, 0x03, b'u',b'i',b'd',
              0x04, 0x05, b'a',b'l',b'i',b'c',b'e',
            0x30, 0x00,        // attributes = []
    ];

    #[test]
    fn parse_search_request_uid_equality() {
        let msg = parse_message(SEARCH_UID_ALICE).unwrap();
        assert_eq!(msg.message_id, 3);
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.base_dn, "ou=people,dc=local");
        assert_eq!(req.scope, Scope::WholeSubtree);
        assert_eq!(req.size_limit, 0);
        assert!(!req.types_only);
        assert!(req.attributes.is_empty());
        let Filter::EqualityMatch { attr, value } = req.filter
            else { panic!("wrong filter") };
        assert_eq!(attr, "uid");
        assert_eq!(value, "alice");
    }

    /// Search over "dc=local", subtree, with the given raw filter bytes.
    fn search_message(size_limit: i64, types_only: bool, filter: Vec<u8>) -> Vec<u8> {
        search_msg(8, "dc=local", 2, size_limit, types_only, filter)
    }

    fn parse_filter_of(filter: Vec<u8>) -> BerResult<Filter> {
        let msg = parse_message(&search_message(0, false, filter))?;
        match msg.operation {
            LdapOperation::SearchRequest(req) => Ok(req.filter),
            _ => panic!("wrong op"),
        }
    }

    #[test]
    fn parse_search_request_size_limit_and_types_only() {
        let present = ber::encode_tlv(0x87, b"objectClass");
        let msg = parse_message(&search_message(25, true, present)).unwrap();
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.size_limit, 25);
        assert!(req.types_only);
        // Negative limits are clamped to "no limit".
        let present = ber::encode_tlv(0x87, b"objectClass");
        let msg = parse_message(&search_message(-1, false, present)).unwrap();
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.size_limit, 0);
    }

    #[test]
    fn parse_search_request_extensible_match_is_unsupported() {
        // extensibleMatch [9] with arbitrary content, wrapped in an AND
        // with a present filter: the rest of the filter still parses.
        let mut and = ber::encode_tlv(0xa9, b"\x81\x03uid\x83\x01x");
        and.extend(ber::encode_tlv(0x87, b"objectClass"));
        let msg = parse_message(&search_message(0, false, ber::encode_tlv(0xa0, &and))).unwrap();
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        let Filter::And(children) = req.filter else { panic!("expected AND") };
        assert!(matches!(children[0], Filter::Unsupported));
        assert!(matches!(children[1], Filter::Present(_)));
    }

    #[test]
    fn parse_search_request_ordering_filters() {
        let mut ava = ber::encode_string("uidNumber");
        ava.extend(ber::encode_string("1000"));
        let msg = parse_message(&search_message(0, false, ber::encode_tlv(0xa5, &ava))).unwrap();
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        let Filter::GreaterOrEqual { attr, value } = req.filter
            else { panic!("expected >=") };
        assert_eq!(attr, "uidNumber");
        assert_eq!(value, "1000");
    }

    #[test]
    fn parse_filter_depth_limit() {
        // Nest NOT filters beyond MAX_FILTER_DEPTH.
        let mut f = ber::encode_tlv(0x87, b"uid");
        for _ in 0..(MAX_FILTER_DEPTH + 2) {
            f = ber::encode_tlv(0xa2, &f);
        }
        assert!(matches!(
            parse_message(&search_message(0, false, f)),
            Err(BerError::NestingTooDeep)
        ));
    }


    // Substring filter parsing (wire level)

    #[test]
    fn parse_substrings_each_component() {
        let f = parse_filter_of(f_substrings("cn", Some("Al"), &[], None)).unwrap();
        let Filter::Substrings { attr, initial, any, final_ } = f else { panic!() };
        assert_eq!((attr.as_str(), initial.as_deref(), any.len(), final_), ("cn", Some("Al"), 0, None));

        let f = parse_filter_of(f_substrings("cn", None, &["li", "ce"], None)).unwrap();
        let Filter::Substrings { initial, any, final_, .. } = f else { panic!() };
        assert_eq!((initial, any, final_), (None, vec!["li".to_string(), "ce".to_string()], None));

        let f = parse_filter_of(f_substrings("cn", None, &[], Some("th"))).unwrap();
        let Filter::Substrings { initial, any, final_, .. } = f else { panic!() };
        assert_eq!((initial, any.len(), final_.as_deref()), (None, 0, Some("th")));

        let f = parse_filter_of(f_substrings("cn", Some("A"), &["i"], Some("h"))).unwrap();
        let Filter::Substrings { initial, any, final_, .. } = f else { panic!() };
        assert_eq!(
            (initial.as_deref(), any, final_.as_deref()),
            (Some("A"), vec!["i".to_string()], Some("h"))
        );
    }

    #[test]
    fn parse_substrings_unknown_subtag_ignored_and_bad_utf8_rejected() {
        // [3] is not a defined substring choice; it is skipped.
        let mut subs = ber::encode_tlv(0x80, b"A");
        subs.extend(ber::encode_tlv(0x83, b"junk"));
        let mut c = ber::encode_string("cn");
        c.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &subs));
        let f = parse_filter_of(ber::encode_tlv(0xa4, &c)).unwrap();
        let Filter::Substrings { initial, any, .. } = f else { panic!() };
        assert_eq!((initial.as_deref(), any.len()), (Some("A"), 0));

        let subs = ber::encode_tlv(0x80, &[0xff, 0xfe]);
        let mut c = ber::encode_string("cn");
        c.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &subs));
        assert!(matches!(
            parse_filter_of(ber::encode_tlv(0xa4, &c)),
            Err(BerError::InvalidUtf8)
        ));
    }

    #[test]
    fn parse_substrings_roundtrip_matches() {
        // (cn=Al*ce Sm*) parsed from the wire matches "Alice Smith".
        let f = parse_filter_of(f_substrings("cn", Some("Al"), &["ce Sm"], None)).unwrap();
        assert!(matches_filter(&f, &attrs(&[("cn", &["Alice Smith"])])));
        assert!(!matches_filter(&f, &attrs(&[("cn", &["Bob Smith"])])));
    }

    // Parse error arms

    #[test]
    fn parse_search_invalid_scope() {
        let msg = search_msg(1, "dc=local", 3, 0, false, f_present("objectClass"));
        assert!(matches!(parse_message(&msg), Err(BerError::InvalidValue)));
    }

    #[test]
    fn parse_search_attribute_list_must_hold_strings() {
        let mut body = ber::encode_string("dc=local");
        body.extend(ber::encode_enumerated(0));
        body.extend(ber::encode_enumerated(0));
        body.extend(ber::encode_integer(0));
        body.extend(ber::encode_integer(0));
        body.extend(ber::encode_tlv(ber::TAG_BOOLEAN, &[0]));
        body.extend(f_present("objectClass"));
        body.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &ber::encode_integer(1)));
        let msg = envelope(1, ber::encode_tlv(APP_SEARCH_REQUEST, &body));
        assert!(matches!(
            parse_message(&msg),
            Err(BerError::UnexpectedTag { expected: 0x04, got: 0x02 })
        ));
    }

    #[test]
    fn parse_search_attribute_list_decoded() {
        let msg = search_msg_attrs(1, "dc=local", 0, 0, false, f_present("x"), &["uid", "cn"]);
        let LdapOperation::SearchRequest(req) = parse_message(&msg).unwrap().operation
            else { panic!() };
        assert_eq!(req.attributes, vec!["uid", "cn"]);
    }

    #[test]
    fn parse_bind_truncated_and_bad_utf8() {
        // No auth choice after the name.
        let mut body = ber::encode_integer(3);
        body.extend(ber::encode_string("alice"));
        let msg = envelope(1, ber::encode_tlv(APP_BIND_REQUEST, &body));
        assert!(matches!(parse_message(&msg), Err(BerError::UnexpectedEof)));
        // Password that is not UTF-8.
        let mut body = ber::encode_integer(3);
        body.extend(ber::encode_string("alice"));
        body.extend(ber::encode_tlv(CTX_SIMPLE_AUTH, &[0xc0]));
        let msg = envelope(1, ber::encode_tlv(APP_BIND_REQUEST, &body));
        assert!(matches!(parse_message(&msg), Err(BerError::InvalidUtf8)));
    }

    #[test]
    fn parse_filter_error_arms() {
        assert!(matches!(
            parse_filter_of(ber::encode_tlv(0x87, &[0xff])),
            Err(BerError::InvalidUtf8)
        ));
        // Equality with a missing value.
        assert!(parse_filter_of(ber::encode_tlv(0xa3, &ber::encode_string("uid"))).is_err());
        // NOT with empty content.
        assert!(matches!(
            parse_filter_of(ber::encode_tlv(0xa2, &[])),
            Err(BerError::UnexpectedEof)
        ));
        // Composite filters parse all children.
        let f = parse_filter_of(f_or(&[f_eq("uid", "a"), f_not(f_le("uidNumber", "5"))])).unwrap();
        let Filter::Or(children) = f else { panic!() };
        assert!(matches!(children[1], Filter::Not(_)));
        assert!(matches!(children[0], Filter::EqualityMatch { .. }));
    }

    #[test]
    fn parse_message_rejects_non_sequence_and_missing_op() {
        assert!(parse_message(&ber::encode_string("x")).is_err());
        let only_id = ber::encode_tlv(ber::TAG_SEQUENCE, &ber::encode_integer(1));
        assert!(matches!(parse_message(&only_id), Err(BerError::UnexpectedEof)));
    }

    #[test]
    fn parse_filter_depth_boundary_accepted() {
        // Exactly MAX_FILTER_DEPTH nested NOTs around a leaf is accepted;
        // the existing test checks that one more is rejected.
        let mut f = f_present("uid");
        for _ in 0..MAX_FILTER_DEPTH {
            f = f_not(f);
        }
        assert!(parse_filter_of(f).is_ok());
    }

    // Property tests

    fn arb_filter() -> impl Strategy<Value = Filter> {
        let leaf = prop_oneof![
            (".{0,8}", ".{0,8}").prop_map(|(attr, value)| Filter::EqualityMatch { attr, value }),
            (".{0,8}", ".{0,8}").prop_map(|(attr, value)| Filter::GreaterOrEqual { attr, value }),
            (".{0,8}", ".{0,8}").prop_map(|(attr, value)| Filter::LessOrEqual { attr, value }),
            ".{0,8}".prop_map(Filter::Present),
            (".{0,8}", proptest::option::of(".{0,4}"),
             proptest::collection::vec(".{0,4}", 0..3), proptest::option::of(".{0,4}"))
                .prop_map(|(attr, initial, any, final_)| Filter::Substrings { attr, initial, any, final_ }),
            Just(Filter::ApproxMatch),
            Just(Filter::Unsupported),
        ];
        leaf.prop_recursive(4, 16, 3, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..3).prop_map(Filter::And),
                proptest::collection::vec(inner.clone(), 0..3).prop_map(Filter::Or),
                inner.prop_map(|f| Filter::Not(Box::new(f))),
            ]
        })
    }

    fn arb_attrs() -> impl Strategy<Value = Attrs> {
        proptest::collection::vec(
            (".{0,8}", proptest::collection::vec(".{0,8}", 0..3)),
            0..4,
        )
    }

    proptest! {
        #[test]
        fn parse_message_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = parse_message(&bytes);
        }

        #[test]
        fn parse_tlv_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = ber::parse_tlv(&bytes);
            let _ = ber::decode_integer(&bytes);
            let _ = ber::decode_enumerated(&bytes);
            let _ = ber::decode_string(&bytes);
            let _ = ber::decode_boolean(&bytes);
        }

        #[test]
        fn mutated_search_never_panics(
            idx in 0usize..80, byte in any::<u8>(), cut in 0usize..80,
        ) {
            // Flip one byte of a valid search and truncate; parsing must
            // return, never panic.
            let mut msg = search_msg(1, "ou=people,dc=local", 2, 0, false,
                f_and(&[f_eq("objectClass", "posixAccount"), f_substrings("cn", Some("A"), &["l"], None)]));
            if idx < msg.len() { msg[idx] = byte; }
            msg.truncate(cut.min(msg.len()));
            let _ = parse_message(&msg);
        }

        #[test]
        fn integer_roundtrip_all_i64(n in any::<i64>()) {
            let enc = ber::encode_integer(n);
            let (dec, rest) = ber::decode_integer(&enc).unwrap();
            prop_assert_eq!(dec, n);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn length_roundtrip_u32(n in any::<u32>()) {
            let enc = ber::encode_length(n as usize);
            let (dec, used) = ber::decode_length(&enc).unwrap();
            prop_assert_eq!(dec, n as usize);
            prop_assert_eq!(used, enc.len());
        }

        #[test]
        fn enumerated_roundtrip(n in any::<u32>()) {
            let enc = ber::encode_enumerated(n);
            let (dec, _) = ber::decode_enumerated(&enc).unwrap();
            prop_assert_eq!(dec, n);
        }

        #[test]
        fn response_roundtrip(id in any::<i64>(), code in any::<u32>(), diag in ".{0,16}") {
            let bytes = encode_response(id, &Response::Bind(LdapResult::error(code, diag)));
            let (got_id, tag, value) = decode_envelope(&bytes);
            prop_assert_eq!(got_id, id);
            prop_assert_eq!(tag, APP_BIND_RESPONSE);
            prop_assert_eq!(result_code(&value), code);
        }

        #[test]
        fn normalize_dn_idempotent(dn in ".{0,40}") {
            let once = normalize_dn(&dn);
            prop_assert_eq!(normalize_dn(&once), once.clone());
            // Splitting never loses or reorders characters.
            prop_assert_eq!(split_rdns(&dn).join(","), dn);
        }

        #[test]
        fn matches_filter_never_panics(f in arb_filter(), a in arb_attrs()) {
            let _ = matches_filter(&f, &a);
        }

        #[test]
        fn leaf_value_never_panics(dn in ".{0,40}", attr in "[a-z]{1,4}", parent in ".{0,20}") {
            let _ = leaf_value(&dn, &attr, &normalize_dn(&parent));
        }
    }

    // Search with AND filter: (&(objectClass=posixAccount)(uid=alice))
    // Outer AND: a0 [len] [child1] [child2]
    //   "objectClass" = 11 chars, "posixAccount" = 12 chars
    //   child1: a3  04 0b [11]  04 0c [12]
    //     content = 2+11+2+12 = 27; a3 1b [27 bytes] = 29
    //   child2: a3 0c  04 03 "uid"  04 05 "alice"  = 14 bytes
    //   AND content: 29 + 14 = 43 = 0x2b; filter: a0 2b [..] = 45 bytes
    //
    // SearchReq content:
    //   04 00 [base=""]  0a 01 02  0a 01 00  02 01 00  02 01 00
    //   01 01 00  [45-byte filter]  30 00
    //   = 2 + 3 + 3 + 3 + 3 + 3 + 45 + 2 = 64 = 0x40
    // msgId: 02 01 04 (3)
    // Seq content: 3 + 2 + 64 = 69 = 0x45
    const SEARCH_AND_FILTER: &[u8] = &[
        0x30, 0x45,
          0x02, 0x01, 0x04,
          0x63, 0x40,
            0x04, 0x00,        // base = ""
            0x0a, 0x01, 0x02,  // scope = wholeSubtree
            0x0a, 0x01, 0x00,
            0x02, 0x01, 0x00,
            0x02, 0x01, 0x00,
            0x01, 0x01, 0x00,
            0xa0, 0x2b,        // AND
              0xa3, 0x1b,      // equalityMatch objectClass=posixAccount
                0x04, 0x0b,
                  b'o',b'b',b'j',b'e',b'c',b't',b'C',b'l',b'a',b's',b's',
                0x04, 0x0c,
                  b'p',b'o',b's',b'i',b'x',b'A',b'c',b'c',b'o',b'u',b'n',b't',
              0xa3, 0x0c,      // equalityMatch uid=alice
                0x04, 0x03, b'u',b'i',b'd',
                0x04, 0x05, b'a',b'l',b'i',b'c',b'e',
            0x30, 0x00,
    ];

    #[test]
    fn parse_search_request_and_filter() {
        let msg = parse_message(SEARCH_AND_FILTER).unwrap();
        assert_eq!(msg.message_id, 4);
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.base_dn, "");
        let Filter::And(children) = req.filter
            else { panic!("expected AND") };
        assert_eq!(children.len(), 2);
        let Filter::EqualityMatch { attr: a1, value: v1 } = &children[0]
            else { panic!() };
        assert_eq!(a1, "objectClass");
        assert_eq!(v1, "posixAccount");
        let Filter::EqualityMatch { attr: a2, value: v2 } = &children[1]
            else { panic!() };
        assert_eq!(a2, "uid");
        assert_eq!(v2, "alice");
    }

    // Message encoding

    #[test]
    fn encode_bind_response_success() {
        let bytes = encode_response(1, &Response::Bind(LdapResult::success()));
        let (id, tag, value) = decode_envelope(&bytes);
        assert_eq!(id, 1);
        assert_eq!(tag, APP_BIND_RESPONSE);
        let (code, _) = ber::decode_enumerated(&value).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn encode_bind_response_error() {
        let bytes = encode_response(
            5,
            &Response::Bind(LdapResult::error(INVALID_CREDENTIALS, "bad password")),
        );
        let (id, _, value) = decode_envelope(&bytes);
        assert_eq!(id, 5);
        let (code, rest) = ber::decode_enumerated(&value).unwrap();
        assert_eq!(code, INVALID_CREDENTIALS);
        let (_matched_dn, rest) = ber::decode_string(rest).unwrap();
        let (diag, _) = ber::decode_string(rest).unwrap();
        assert_eq!(diag, "bad password");
    }

    #[test]
    fn encode_generic_response_uses_given_tag() {
        let bytes = encode_response(2, &Response::Generic {
            tag: 0x69,
            result: LdapResult::error(UNWILLING_TO_PERFORM, "read-only"),
        });
        let (id, tag, value) = decode_envelope(&bytes);
        assert_eq!(id, 2);
        assert_eq!(tag, 0x69);
        let (code, _) = ber::decode_enumerated(&value).unwrap();
        assert_eq!(code, UNWILLING_TO_PERFORM);
    }

    #[test]
    fn notice_of_disconnection_shape() {
        let bytes = notice_of_disconnection("bad");
        let (id, tag, value) = decode_envelope(&bytes);
        assert_eq!(id, 0);
        assert_eq!(tag, APP_EXTENDED_RESPONSE);
        let (code, rest) = ber::decode_enumerated(&value).unwrap();
        assert_eq!(code, PROTOCOL_ERROR);
        let (_, rest) = ber::decode_string(rest).unwrap();
        let (_, rest) = ber::decode_string(rest).unwrap();
        let (tag, name, rest) = ber::parse_tlv(rest).unwrap();
        assert_eq!(tag, CTX_RESPONSE_NAME);
        assert_eq!(name, NOTICE_OF_DISCONNECTION_OID.as_bytes());
        assert!(rest.is_empty());
    }

    #[test]
    fn encode_search_entry_roundtrip_shape() {
        let entry = SearchResultEntry {
            dn: "uid=alice,dc=local".into(),
            attributes: attrs(&[("uid", &["alice"]), ("cn", &[])]),
        };
        let bytes = encode_response(3, &Response::SearchEntry(entry));
        let (_, tag, value) = decode_envelope(&bytes);
        assert_eq!(tag, APP_SEARCH_RESULT_ENTRY);
        let (dn, rest) = ber::decode_string(&value).unwrap();
        assert_eq!(dn, "uid=alice,dc=local");
        let (attr_list, _) = ber::expect_tag(rest, ber::TAG_SEQUENCE).unwrap();
        // Two attribute SEQUENCEs, the second with an empty SET.
        let (a1, rest) = ber::expect_tag(attr_list, ber::TAG_SEQUENCE).unwrap();
        let (name, _) = ber::decode_string(a1).unwrap();
        assert_eq!(name, "uid");
        let (a2, rest) = ber::expect_tag(rest, ber::TAG_SEQUENCE).unwrap();
        assert!(rest.is_empty());
        let (name, set) = ber::decode_string(a2).unwrap();
        assert_eq!(name, "cn");
        let (set, _) = ber::expect_tag(set, ber::TAG_SET).unwrap();
        assert!(set.is_empty());
    }
}
