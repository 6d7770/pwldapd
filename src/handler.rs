/// Per-connection LDAP request handler.
use crate::config::{AttrValue, Config};
use crate::ldap::{
    self, Attrs, LdapOperation, LdapResult, Response, Scope, SearchRequest,
    SearchResultEntry,
};
use crate::passwd::{Directory, Group, User};
use crate::pam_auth;
use anyhow::Result;
use std::cell::OnceCell;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Account data source shared by all connections.
pub type SharedDirectory = Arc<dyn Directory + Send + Sync>;

pub async fn handle_connection<S>(
    mut stream: S,
    config: Arc<Config>,
    dir: SharedDirectory,
    peer: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut bound_as: Option<String> = None;
    loop {
        let read = read_ldap_message(&mut stream);
        let read = match config.idle_timeout {
            Some(limit) => match tokio::time::timeout(limit, read).await {
                Ok(r) => r,
                Err(_) => {
                    debug!("{peer} idle timeout");
                    return Ok(());
                }
            },
            None => read.await,
        };
        let msg_bytes = match read {
            Ok(b) => b,
            Err(e)
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                debug!("{peer} disconnected");
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                warn!("{peer} bad message framing: {e}");
                let _ = stream
                    .write_all(&ldap::notice_of_disconnection("Protocol error"))
                    .await;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let msg = match ldap::parse_message(&msg_bytes) {
            Ok(m) => m,
            Err(e) => {
                // RFC 4511 4.4.1: a malformed PDU gets an unsolicited
                // Notice of Disconnection, after which we close.
                warn!("{peer} failed to parse LDAP message: {e}");
                let _ = stream
                    .write_all(&ldap::notice_of_disconnection("Protocol error"))
                    .await;
                return Ok(());
            }
        };
        let op = std::mem::discriminant(&msg.operation);
        debug!("{peer} id={} op={op:?}", msg.message_id);

        match msg.operation {
            LdapOperation::UnbindRequest => {
                debug!("{peer} UnbindRequest: closing");
                return Ok(());
            }
            LdapOperation::AbandonRequest(id) => {
                // Searches complete synchronously, so there is never
                // anything in flight to abandon.
                debug!("{peer} AbandonRequest for msg {id}");
            }
            LdapOperation::BindRequest(req) => {
                let (result, username) =
                    do_bind(&req, &config, &dir, peer).await;
                bound_as = username;
                send(&mut stream, msg.message_id, &Response::Bind(result))
                    .await?;
            }
            LdapOperation::SearchRequest(req) => {
                let authorized = match &bound_as {
                    Some(u) => config.bind_permitted(u),
                    None    => config.require_bind.is_empty(),
                };
                do_search(
                    &req, msg.message_id, &config, &dir, &mut stream, authorized,
                )
                .await?;
            }
            LdapOperation::Unsupported { tag, response_tag } => {
                debug!("{peer} unsupported operation {tag:#04x}");
                let result = LdapResult::error(
                    ldap::UNWILLING_TO_PERFORM,
                    "Operation not supported by this read-only server",
                );
                send(
                    &mut stream,
                    msg.message_id,
                    &Response::Generic { tag: response_tag, result },
                )
                .await?;
            }
        }
    }
}

async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message_id: i64,
    resp: &Response,
) -> Result<()> {
    stream.write_all(&ldap::encode_response(message_id, resp)).await?;
    Ok(())
}

/// Derive the account name to authenticate from a bind name. Accepted forms
/// are `uid=<name>,<users_dn>` (any case, optional whitespace) and a bare
/// account name. Any other DN, including one with a `uid=` component under
/// a foreign parent, is rejected.
fn bind_username(name: &str, config: &Config) -> Option<String> {
    let name = name.trim();
    let user = if name.contains('=') {
        let users_dn = ldap::normalize_dn(&config.users_dn());
        ldap::leaf_value(name, "uid", &users_dn)?
    } else if name.contains(',') {
        return None;
    } else {
        name
    };
    pam_auth::is_valid_username(user).then(|| user.to_string())
}

async fn do_bind(
    req: &ldap::BindRequest,
    config: &Arc<Config>,
    dir: &SharedDirectory,
    peer: &str,
) -> (LdapResult, Option<String>) {
    let invalid = || LdapResult::error(ldap::INVALID_CREDENTIALS, "Invalid credentials");
    let password = match &req.auth {
        ldap::BindAuth::Simple(pw) => pw,
        ldap::BindAuth::Unsupported => {
            info!("{peer} bind failed (unsupported auth method) dn={}", req.name);
            return (
                LdapResult::error(
                    ldap::AUTH_METHOD_NOT_SUPPORTED,
                    "Only simple binds are supported",
                ),
                None,
            );
        }
    };
    if req.name.is_empty() && password.is_empty() {
        info!("{peer} anonymous bind");
        return (LdapResult::success(), None);
    }
    if password.is_empty() {
        info!("{peer} bind failed (empty password) dn={}", req.name);
        return (invalid(), None);
    }
    let Some(username) = bind_username(&req.name, config) else {
        info!("{peer} bind failed (unacceptable bind DN) dn={}", req.name);
        return (invalid(), None);
    };
    let password = password.clone();
    let config = Arc::clone(config);
    let dir = Arc::clone(dir);
    let username_clone = username.clone();
    let ok = tokio::task::spawn_blocking(move || {
        if !pam_auth::authenticate(&username_clone, &password) {
            return false;
        }
        // Deny bind if the user's UID falls outside the configured range.
        // This keeps authentication consistent with what the directory serves.
        match dir.user_by_name(&username_clone) {
            Some(u) => config.uid_allowed(u.uid),
            // Authenticated via PAM but no passwd entry; permit the bind.
            None => true,
        }
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!("PAM task panicked: {e}");
        false
    });
    if ok {
        info!("{peer} bind ok dn={}", req.name);
        (LdapResult::success(), Some(username))
    } else {
        info!("{peer} bind failed dn={}", req.name);
        (invalid(), None)
    }
}

async fn do_search<S: AsyncWrite + Unpin>(
    req: &SearchRequest,
    message_id: i64,
    config: &Arc<Config>,
    dir: &SharedDirectory,
    stream: &mut S,
    authorized: bool,
) -> Result<()> {
    if !authorized {
        let result = LdapResult::error(
            ldap::INSUFFICIENT_ACCESS_RIGHTS,
            "Bind required",
        );
        return send(stream, message_id, &Response::SearchDone(result)).await;
    }
    let req2 = req.clone();
    let config2 = Arc::clone(config);
    let dir2 = Arc::clone(dir);
    let entries = tokio::task::spawn_blocking(move || {
        collect_entries(&req2, &config2, dir2.as_ref())
    })
    .await?;

    let limit = match usize::try_from(req.size_limit) {
        Ok(0) | Err(_) => usize::MAX,
        Ok(n) => n,
    };
    let mut result = LdapResult::success();
    let mut matching = entries
        .iter()
        .filter(|e| ldap::matches_filter(&req.filter, &e.attributes));
    for entry in matching.by_ref().take(limit) {
        let mut selected = select_attributes(entry, &req.attributes);
        if req.types_only {
            for (_, values) in &mut selected.attributes {
                values.clear();
            }
        }
        send(stream, message_id, &Response::SearchEntry(selected)).await?;
    }
    if matching.next().is_some() {
        result = LdapResult::error(ldap::SIZE_LIMIT_EXCEEDED, "");
    }
    send(stream, message_id, &Response::SearchDone(result)).await
}

// Entry collection

/// Lazily evaluated view of the directory restricted by the configured
/// UID/GID ranges. Enumeration happens at most once per search and only
/// when a request actually needs it; single-entry lookups go straight to
/// the name-based lookups.
struct Lookup<'a> {
    dir: &'a dyn Directory,
    config: &'a Config,
    users: OnceCell<Vec<User>>,
    groups: OnceCell<Vec<Group>>,
    served_names: OnceCell<HashSet<String>>,
}

impl<'a> Lookup<'a> {
    fn new(dir: &'a dyn Directory, config: &'a Config) -> Self {
        Self {
            dir,
            config,
            users: OnceCell::new(),
            groups: OnceCell::new(),
            served_names: OnceCell::new(),
        }
    }

    /// All served users.
    fn users(&self) -> &[User] {
        self.users.get_or_init(|| {
            self.dir
                .all_users()
                .into_iter()
                .filter(|u| self.config.uid_allowed(u.uid))
                .collect()
        })
    }

    /// All served groups, with memberUid trimmed to served users.
    fn groups(&self) -> &[Group] {
        self.groups.get_or_init(|| {
            self.dir
                .all_groups()
                .into_iter()
                .filter(|g| self.group_allowed(g.gid))
                .map(|g| self.trim_members(g))
                .collect()
        })
    }

    /// A group is served if its GID is in range or it is the primary group
    /// of a served user.
    fn group_allowed(&self, gid: u32) -> bool {
        self.config.gid_allowed(gid)
            || self.users().iter().any(|u| u.gid == gid)
    }

    fn user(&self, name: &str) -> Option<User> {
        if let Some(u) = self.dir.user_by_name(name) {
            return self.config.uid_allowed(u.uid).then_some(u);
        }
        // LDAP uid matching is case-insensitive; POSIX names are not.
        // Fall back to a scan only when an exact lookup misses.
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            return self
                .users()
                .iter()
                .find(|u| u.name.eq_ignore_ascii_case(name))
                .cloned();
        }
        None
    }

    fn group(&self, name: &str) -> Option<Group> {
        let found = match self.dir.group_by_name(name) {
            Some(g) => Some(g),
            None if name.bytes().any(|b| b.is_ascii_uppercase()) => self
                .dir
                .all_groups()
                .into_iter()
                .find(|g| g.name.eq_ignore_ascii_case(name)),
            None => None,
        };
        let g = found?;
        self.group_allowed(g.gid).then(|| self.trim_members(g))
    }

    /// Remove members that are not served users, so that accounts excluded
    /// by uid_ranges are not revealed through group membership.
    fn trim_members(&self, mut g: Group) -> Group {
        if !self.config.uid_ranges.is_empty() {
            let served = self.served_names.get_or_init(|| {
                self.users().iter().map(|u| u.name.clone()).collect()
            });
            g.members.retain(|m| served.contains(m));
        }
        g
    }

    /// Entry for a leaf DN directly under the people or groups OU.
    fn leaf_entry(
        &self,
        dn: &str,
        users_dn: &str,
        groups_dn: &str,
    ) -> Option<SearchResultEntry> {
        if let Some(uid) = ldap::leaf_value(dn, "uid", users_dn) {
            self.user(uid).map(|u| user_entry(&u, self.config))
        } else if let Some(cn) = ldap::leaf_value(dn, "cn", groups_dn) {
            self.group(cn).map(|g| group_entry(&g, self.config))
        } else {
            None
        }
    }
}

fn collect_entries(
    req: &SearchRequest,
    config: &Config,
    dir: &dyn Directory,
) -> Vec<SearchResultEntry> {
    let lookup = Lookup::new(dir, config);
    let base = ldap::normalize_dn(&req.base_dn);
    let users_dn = ldap::normalize_dn(&config.users_dn());
    let groups_dn = ldap::normalize_dn(&config.groups_dn());
    let root_dn = ldap::normalize_dn(&config.base_dn);

    let mut out = Vec::new();

    if base.is_empty() {
        if req.scope == Scope::Base {
            out.push(make_root_dse(config));
        }
        return out;
    }

    let people_ou = || make_ou_entry(&config.users_dn(), "people");
    let groups_ou = || make_ou_entry(&config.groups_dn(), "groups");
    let all_users = |out: &mut Vec<SearchResultEntry>| {
        out.extend(lookup.users().iter().map(|u| user_entry(u, config)));
    };
    let all_groups = |out: &mut Vec<SearchResultEntry>| {
        out.extend(lookup.groups().iter().map(|g| group_entry(g, config)));
    };

    match req.scope {
        Scope::Base => {
            if base == root_dn {
                out.push(make_base_entry(config));
            } else if base == users_dn {
                out.push(people_ou());
            } else if base == groups_dn {
                out.push(groups_ou());
            } else {
                out.extend(lookup.leaf_entry(&req.base_dn, &users_dn, &groups_dn));
            }
        }
        Scope::OneLevel => {
            if base == root_dn {
                out.push(people_ou());
                out.push(groups_ou());
            } else if base == users_dn {
                all_users(&mut out);
            } else if base == groups_dn {
                all_groups(&mut out);
            }
        }
        Scope::WholeSubtree => {
            if base == root_dn {
                out.push(make_base_entry(config));
                out.push(people_ou());
                out.push(groups_ou());
                all_users(&mut out);
                all_groups(&mut out);
            } else if base == users_dn {
                out.push(people_ou());
                all_users(&mut out);
            } else if base == groups_dn {
                out.push(groups_ou());
                all_groups(&mut out);
            } else {
                out.extend(lookup.leaf_entry(&req.base_dn, &users_dn, &groups_dn));
            }
        }
    }

    out
}

// Entry constructors

fn make_root_dse(config: &Config) -> SearchResultEntry {
    SearchResultEntry {
        dn: String::new(),
        attributes: vec![
            ("objectClass".into(), vec!["top".into()]),
            ("namingContexts".into(), vec![config.base_dn.clone()]),
            ("supportedLDAPVersion".into(), vec!["3".into()]),
            ("vendorName".into(), vec!["pwldapd".into()]),
        ],
    }
}

fn make_base_entry(config: &Config) -> SearchResultEntry {
    let dc = ldap::split_rdns(&config.base_dn)
        .into_iter()
        .map(str::trim)
        .find_map(|p| {
            let (attr, value) = p.split_once('=')?;
            attr.trim().eq_ignore_ascii_case("dc").then(|| value.trim())
        })
        .unwrap_or("local");
    SearchResultEntry {
        dn: config.base_dn.clone(),
        attributes: vec![
            (
                "objectClass".into(),
                vec!["top".into(), "dcObject".into(), "organization".into()],
            ),
            ("dc".into(), vec![dc.into()]),
            ("o".into(), vec![dc.into()]),
        ],
    }
}

fn make_ou_entry(dn: &str, ou: &str) -> SearchResultEntry {
    SearchResultEntry {
        dn: dn.to_string(),
        attributes: vec![
            (
                "objectClass".into(),
                vec!["top".into(), "organizationalUnit".into()],
            ),
            ("ou".into(), vec![ou.into()]),
        ],
    }
}

fn user_entry(u: &User, config: &Config) -> SearchResultEntry {
    let dn = format!("uid={},{}", u.name, config.users_dn());

    let gecos_fields: Vec<&str> = u.gecos.splitn(5, ',')
        .map(str::trim)
        .collect();
    let gecos_field = |i: usize| -> Option<&str> {
        gecos_fields.get(i).copied().filter(|s| !s.is_empty())
    };

    let cn = gecos_field(0).unwrap_or(&u.name).to_string();
    let words: Vec<&str> = cn.split_whitespace().collect();
    let sn = words.last().copied().unwrap_or(&u.name).to_string();
    let given_name = if words.len() >= 2 {
        Some(words[0].to_string())
    } else {
        None
    };

    let mut attrs: Attrs = vec![
        (
            "objectClass".into(),
            vec![
                "top".into(),
                "posixAccount".into(),
                "inetOrgPerson".into(),
            ],
        ),
        ("uid".into(), vec![u.name.clone()]),
        ("cn".into(), vec![cn.clone()]),
        ("sn".into(), vec![sn.clone()]),
        ("uidNumber".into(), vec![u.uid.to_string()]),
        ("gidNumber".into(), vec![u.gid.to_string()]),
        ("homeDirectory".into(), vec![u.home_dir.clone()]),
        ("loginShell".into(), vec![u.shell.clone()]),
        ("gecos".into(), vec![u.gecos.clone()]),
    ];
    if let Some(v) = given_name {
        attrs.push(("givenName".into(), vec![v]));
    }
    if let Some(v) = gecos_field(1) {
        attrs.push(("roomNumber".into(), vec![v.to_string()]));
    }
    if let Some(v) = gecos_field(2) {
        attrs.push(("telephoneNumber".into(), vec![v.to_string()]));
    }
    if let Some(v) = gecos_field(3) {
        attrs.push(("homePhone".into(), vec![v.to_string()]));
    }
    apply_user_attributes(&mut attrs, u, &cn, &sn, config);
    SearchResultEntry { dn, attributes: attrs }
}

fn group_entry(g: &Group, config: &Config) -> SearchResultEntry {
    let dn = format!("cn={},{}", g.name, config.groups_dn());
    let mut attrs: Attrs = vec![
        ("objectClass".into(), vec!["top".into(), "posixGroup".into()]),
        ("cn".into(), vec![g.name.clone()]),
        ("gidNumber".into(), vec![g.gid.to_string()]),
    ];
    if !g.members.is_empty() {
        attrs.push(("memberUid".into(), g.members.clone()));
    }
    SearchResultEntry { dn, attributes: attrs }
}

// Attribute extension

/// Expand `{placeholder}` sequences in `template` using the given user fields.
/// Templates are validated at startup, so every placeholder present is known.
fn expand_template(
    template: &str,
    user: &User,
    cn: &str,
    sn: &str,
) -> String {
    let uid_n = user.uid.to_string();
    let gid_n = user.gid.to_string();
    let vars: &[(&str, &str)] = &[
        ("uid",           &user.name),
        ("cn",            cn),
        ("sn",            sn),
        ("uidNumber",     &uid_n),
        ("gidNumber",     &gid_n),
        ("homeDirectory", &user.home_dir),
        ("shell",         &user.shell),
        ("gecos",         &user.gecos),
    ];
    let mut result = template.to_string();
    for (key, val) in vars {
        result = result.replace(&format!("{{{key}}}"), val);
    }
    result
}

/// Replace an existing attribute's values or append a new attribute.
fn set_attr(attrs: &mut Attrs, name: &str, value: String) {
    match attrs.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        Some(existing) => existing.1 = vec![value],
        None => attrs.push((name.to_string(), vec![value])),
    }
}

/// Apply `config.user_attributes` and per-user overrides to an in-progress
/// attribute list. Called at the end of `user_entry()`.
///
/// Precedence (highest first):
///   1. `config.user_overrides[username][attr]`: fixed string
///   2. `config.user_attributes[attr]`: template or fixed string
///   3. Built-in attributes assembled earlier
///
/// Protected attributes (objectClass, uid, uidNumber, gidNumber) have
/// already been removed from both maps at config load.
fn apply_user_attributes(
    attrs: &mut Attrs,
    user: &User,
    cn: &str,
    sn: &str,
    config: &Config,
) {
    let overrides = config.user_overrides.get(&user.name);
    // Attribute names handled via user_attributes, so the remaining
    // per-user overrides can skip them.
    let mut handled: HashSet<String> = HashSet::new();

    for (attr_name, attr_val) in &config.user_attributes {
        handled.insert(attr_name.to_lowercase());
        let value = match overrides.and_then(|m| m.get(attr_name)) {
            Some(ov) => ov.clone(),
            None => match attr_val {
                AttrValue::Fixed(s) => s.clone(),
                AttrValue::Template(t) => expand_template(t, user, cn, sn),
            },
        };
        set_attr(attrs, attr_name, value);
    }

    if let Some(overrides) = overrides {
        for (attr_name, value) in overrides {
            if !handled.contains(&attr_name.to_lowercase()) {
                set_attr(attrs, attr_name, value.clone());
            }
        }
    }
}

// Helpers

/// Filter an entry's attributes to only those listed in `requested`.
/// An empty list or `"*"` means all attributes; `"1.1"` alone means none
/// (RFC 4511 section 4.5.1.8).
fn select_attributes(
    entry: &SearchResultEntry,
    requested: &[String],
) -> SearchResultEntry {
    if requested.is_empty() || requested.iter().any(|a| a == "*") {
        return entry.clone();
    }
    if requested.len() == 1 && requested[0] == "1.1" {
        return SearchResultEntry { dn: entry.dn.clone(), attributes: vec![] };
    }
    let attributes = entry
        .attributes
        .iter()
        .filter(|(name, _)| {
            requested.iter().any(|r| r.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect();
    SearchResultEntry { dn: entry.dn.clone(), attributes }
}

// Wire reading

/// Largest LDAP PDU accepted from a client. Requests to this server are
/// tiny; the limit mainly bounds the allocation a client can trigger.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

fn invalid_data(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

/// Read one complete BER TLV (an LDAPMessage) from the stream.
async fn read_ldap_message<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut header = head.to_vec();

    let content_len = if head[1] & 0x80 == 0 {
        head[1] as usize
    } else {
        let n = (head[1] & 0x7f) as usize;
        // Indefinite form (n == 0) is forbidden by LDAP; more than four
        // length octets cannot describe a message we would accept.
        if n == 0 || n > 4 {
            return Err(invalid_data(format!(
                "unsupported BER length form ({n} octets)"
            )));
        }
        let mut extra = vec![0u8; n];
        stream.read_exact(&mut extra).await?;
        header.extend_from_slice(&extra);
        extra.iter().fold(0usize, |len, b| (len << 8) | *b as usize)
    };

    if content_len > MAX_MESSAGE_BYTES {
        return Err(invalid_data(format!(
            "LDAP message too large ({content_len} bytes)"
        )));
    }

    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;
    header.extend_from_slice(&content);
    Ok(Zeroizing::new(header))
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;
    use crate::ber;
    use crate::ldap::{Filter, Scope, SearchRequest};
    use std::collections::HashMap;

    // Test fixtures

    /// In-memory directory for tests.
    struct MemDb {
        users: Vec<User>,
        groups: Vec<Group>,
    }

    impl Directory for MemDb {
        fn all_users(&self) -> Vec<User> { self.users.clone() }
        fn all_groups(&self) -> Vec<Group> { self.groups.clone() }
        fn user_by_name(&self, name: &str) -> Option<User> {
            self.users.iter().find(|u| u.name == name).cloned()
        }
        fn group_by_name(&self, name: &str) -> Option<Group> {
            self.groups.iter().find(|g| g.name == name).cloned()
        }
    }

    fn db() -> MemDb {
        MemDb { users: users(), groups: groups() }
    }

    fn cfg() -> Config {
        Config::for_test()
    }

    fn cfg_with(f: impl FnOnce(&mut Config)) -> Config {
        let mut c = Config::for_test();
        f(&mut c);
        c
    }

    fn user(name: &str, uid: u32, gid: u32, gecos: &str) -> User {
        User {
            name: name.into(),
            uid,
            gid,
            gecos: gecos.into(),
            home_dir: format!("/home/{name}"),
            shell: "/bin/bash".into(),
        }
    }

    fn users() -> Vec<User> {
        vec![
            user("alice", 1001, 1001, "Alice Smith,,,"),
            user("bob", 1002, 1002, "Bob Jones"),
        ]
    }

    fn group(name: &str, gid: u32, members: &[&str]) -> Group {
        Group {
            name: name.into(),
            gid,
            members: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn groups() -> Vec<Group> {
        vec![
            group("staff", 200, &["alice", "bob"]),
            group("wheel", 201, &["alice"]),
            group("empty", 202, &[]),
        ]
    }

    fn present() -> Filter {
        Filter::Present("objectClass".into())
    }

    fn search(base: &str, scope: Scope, filter: Filter) -> SearchRequest {
        SearchRequest {
            base_dn: base.into(),
            scope,
            size_limit: 0,
            types_only: false,
            filter,
            attributes: vec![],
        }
    }

    fn collect(req: &SearchRequest, cfg: &Config, db: &MemDb) -> Vec<SearchResultEntry> {
        collect_entries(req, cfg, db)
    }

    fn dn_set(entries: &[SearchResultEntry]) -> Vec<String> {
        let mut dns: Vec<String> =
            entries.iter().map(|e| e.dn.clone()).collect();
        dns.sort();
        dns
    }

    fn attr_values<'a>(
        entry: &'a SearchResultEntry,
        name: &str,
    ) -> Vec<&'a str> {
        entry.attributes.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, vs)| vs.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    // Root DSE

    #[test]
    fn root_dse_base_scope() {
        let req = search("", Scope::Base, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "");
        let nc = attr_values(&entries[0], "namingContexts");
        assert!(nc.contains(&"dc=example,dc=com"));
    }

    #[test]
    fn root_dse_not_returned_for_one_level() {
        let req = search("", Scope::OneLevel, present());
        assert!(collect(&req, &cfg(), &db()).is_empty());
    }

    // Base DN

    #[test]
    fn base_dn_base_scope() {
        let req = search("dc=example,dc=com", Scope::Base, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "dc=example,dc=com");
        assert!(attr_values(&entries[0], "objectClass").contains(&"dcObject"));
        assert_eq!(attr_values(&entries[0], "dc"), vec!["example"]);
    }

    #[test]
    fn base_dn_case_and_whitespace_insensitive() {
        let req = search("DC=EXAMPLE, DC=COM", Scope::Base, present());
        assert_eq!(collect(&req, &cfg(), &db()).len(), 1);
    }

    #[test]
    fn base_dn_one_level_returns_ous() {
        let req = search("dc=example,dc=com", Scope::OneLevel, present());
        let dns = dn_set(&collect(&req, &cfg(), &db()));
        assert_eq!(dns, vec![
            "ou=groups,dc=example,dc=com",
            "ou=people,dc=example,dc=com",
        ]);
    }

    #[test]
    fn base_dn_subtree_returns_everything() {
        let req = search("dc=example,dc=com", Scope::WholeSubtree, present());
        // base + 2 OUs + 2 users + 3 groups = 8
        assert_eq!(collect(&req, &cfg(), &db()).len(), 8);
    }

    // Users OU

    #[test]
    fn users_ou_base_scope() {
        let req = search("ou=people,dc=example,dc=com", Scope::Base, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "ou=people,dc=example,dc=com");
        let oc = attr_values(&entries[0], "objectClass");
        assert!(oc.contains(&"organizationalUnit"));
    }

    #[test]
    fn users_ou_one_level_returns_all_users() {
        let req = search("ou=people,dc=example,dc=com", Scope::OneLevel, present());
        let dns = dn_set(&collect(&req, &cfg(), &db()));
        assert_eq!(dns, vec![
            "uid=alice,ou=people,dc=example,dc=com",
            "uid=bob,ou=people,dc=example,dc=com",
        ]);
    }

    #[test]
    fn users_ou_subtree_includes_ou_entry() {
        let req = search("ou=people,dc=example,dc=com", Scope::WholeSubtree, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 3); // OU + 2 users
        assert!(entries.iter().any(|e| e.dn == "ou=people,dc=example,dc=com"));
    }

    // Groups OU

    #[test]
    fn groups_ou_one_level_returns_all_groups() {
        let req = search("ou=groups,dc=example,dc=com", Scope::OneLevel, present());
        let dns = dn_set(&collect(&req, &cfg(), &db()));
        assert_eq!(dns, vec![
            "cn=empty,ou=groups,dc=example,dc=com",
            "cn=staff,ou=groups,dc=example,dc=com",
            "cn=wheel,ou=groups,dc=example,dc=com",
        ]);
    }

    // Specific entry lookups

    #[test]
    fn user_base_scope_by_dn() {
        let req = search("uid=alice,ou=people,dc=example,dc=com", Scope::Base, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "uid=alice,ou=people,dc=example,dc=com");
    }

    #[test]
    fn user_leaf_lookup_tolerates_case_and_spaces() {
        for scope in [Scope::Base, Scope::WholeSubtree] {
            let req = search("UID=Alice , OU=People,dc=example,dc=com", scope, present());
            let entries = collect(&req, &cfg(), &db());
            assert_eq!(entries.len(), 1, "{scope:?}");
            assert_eq!(entries[0].dn, "uid=alice,ou=people,dc=example,dc=com");
        }
    }

    #[test]
    fn user_base_scope_nonexistent() {
        let req = search("uid=nobody,ou=people,dc=example,dc=com", Scope::Base, present());
        assert!(collect(&req, &cfg(), &db()).is_empty());
    }

    #[test]
    fn user_leaf_under_wrong_parent_is_empty() {
        let req = search("uid=alice,ou=groups,dc=example,dc=com", Scope::Base, present());
        assert!(collect(&req, &cfg(), &db()).is_empty());
    }

    #[test]
    fn group_base_scope_by_dn() {
        let req = search("cn=staff,ou=groups,dc=example,dc=com", Scope::Base, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=staff,ou=groups,dc=example,dc=com");
    }

    #[test]
    fn group_subtree_by_dn() {
        let req = search("cn=Wheel,ou=groups,dc=example,dc=com", Scope::WholeSubtree, present());
        let entries = collect(&req, &cfg(), &db());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=wheel,ou=groups,dc=example,dc=com");
    }

    // Filter application

    #[test]
    fn search_filters_by_uid() {
        let req = search(
            "ou=people,dc=example,dc=com",
            Scope::OneLevel,
            Filter::EqualityMatch { attr: "uid".into(), value: "alice".into() },
        );
        let all = collect(&req, &cfg(), &db());
        let filtered: Vec<_> = all.iter()
            .filter(|e| ldap::matches_filter(&req.filter, &e.attributes))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(attr_values(filtered[0], "uid"), vec!["alice"]);
    }

    // Entry construction

    #[test]
    fn user_entry_attributes() {
        let entry = user_entry(&users()[0], &cfg());
        assert_eq!(entry.dn, "uid=alice,ou=people,dc=example,dc=com");
        assert_eq!(attr_values(&entry, "uid"), vec!["alice"]);
        assert_eq!(attr_values(&entry, "uidNumber"), vec!["1001"]);
        assert_eq!(attr_values(&entry, "gidNumber"), vec!["1001"]);
        assert_eq!(attr_values(&entry, "homeDirectory"), vec!["/home/alice"]);
        assert_eq!(attr_values(&entry, "loginShell"), vec!["/bin/bash"]);
        assert_eq!(attr_values(&entry, "cn"), vec!["Alice Smith"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["Smith"]);
        assert_eq!(attr_values(&entry, "givenName"), vec!["Alice"]);
        // empty gecos fields: no roomNumber/telephoneNumber/homePhone
        assert!(attr_values(&entry, "roomNumber").is_empty());
        assert!(attr_values(&entry, "telephoneNumber").is_empty());
        assert!(attr_values(&entry, "homePhone").is_empty());
        assert!(attr_values(&entry, "objectClass").contains(&"posixAccount"));
        assert!(attr_values(&entry, "objectClass").contains(&"inetOrgPerson"));
    }

    #[test]
    fn user_entry_full_gecos() {
        let u = user("bob", 1002, 1002, "Bob Jones,Room 42,+1-555-0100,+1-555-0101,extra");
        let entry = user_entry(&u, &cfg());
        assert_eq!(attr_values(&entry, "cn"), vec!["Bob Jones"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["Jones"]);
        assert_eq!(attr_values(&entry, "givenName"), vec!["Bob"]);
        assert_eq!(attr_values(&entry, "roomNumber"), vec!["Room 42"]);
        assert_eq!(attr_values(&entry, "telephoneNumber"), vec!["+1-555-0100"]);
        assert_eq!(attr_values(&entry, "homePhone"), vec!["+1-555-0101"]);
    }

    #[test]
    fn user_entry_single_name_no_given_name() {
        let entry = user_entry(&user("root", 0, 0, "root"), &cfg());
        assert_eq!(attr_values(&entry, "cn"), vec!["root"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["root"]);
        assert!(attr_values(&entry, "givenName").is_empty());
    }

    #[test]
    fn user_entry_empty_gecos_uses_name() {
        let entry = user_entry(&user("daemon", 1, 1, ""), &cfg());
        assert_eq!(attr_values(&entry, "cn"), vec!["daemon"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["daemon"]);
        assert!(attr_values(&entry, "givenName").is_empty());
    }

    #[test]
    fn user_entry_three_word_name() {
        let entry = user_entry(&user("jsmith", 1003, 1003, "John Paul Smith"), &cfg());
        assert_eq!(attr_values(&entry, "cn"),        vec!["John Paul Smith"]);
        assert_eq!(attr_values(&entry, "sn"),        vec!["Smith"]);
        assert_eq!(attr_values(&entry, "givenName"), vec!["John"]);
    }

    #[test]
    fn group_entry_with_members() {
        let entry = group_entry(&groups()[0], &cfg());
        assert_eq!(entry.dn, "cn=staff,ou=groups,dc=example,dc=com");
        assert_eq!(attr_values(&entry, "cn"), vec!["staff"]);
        assert_eq!(attr_values(&entry, "gidNumber"), vec!["200"]);
        let mut members = attr_values(&entry, "memberUid");
        members.sort();
        assert_eq!(members, vec!["alice", "bob"]);
        assert!(attr_values(&entry, "objectClass").contains(&"posixGroup"));
    }

    #[test]
    fn group_entry_no_members_omits_memberuid() {
        let entry = group_entry(&groups()[2], &cfg());
        assert!(attr_values(&entry, "memberUid").is_empty());
    }

    #[test]
    fn base_entry_dc_from_any_position_and_case() {
        let cfg = cfg_with(|c| c.base_dn = "o=Org, DC=Corp,dc=com".into());
        let entry = make_base_entry(&cfg);
        assert_eq!(attr_values(&entry, "dc"), vec!["Corp"]);
    }

    // UID range filtering

    #[test]
    fn uid_range_excludes_users_outside_range() {
        let cfg = cfg_with(|c| c.uid_ranges = vec![1001..=1001]);
        let req = search("ou=people,dc=example,dc=com", Scope::OneLevel, present());
        let dns = dn_set(&collect(&req, &cfg, &db()));
        assert_eq!(dns, vec!["uid=alice,ou=people,dc=example,dc=com"]);
    }

    #[test]
    fn uid_range_multiple_ranges() {
        let cfg = cfg_with(|c| c.uid_ranges = vec![1001..=1001, 1002..=1002]);
        let req = search("ou=people,dc=example,dc=com", Scope::OneLevel, present());
        assert_eq!(collect(&req, &cfg, &db()).len(), 2);
    }

    #[test]
    fn uid_filtered_base_scope_excluded_user_returns_empty() {
        let cfg = cfg_with(|c| c.uid_ranges = vec![1002..=1002]); // bob only
        let req = search("uid=alice,ou=people,dc=example,dc=com", Scope::Base, present());
        assert!(collect(&req, &cfg, &db()).is_empty());
        let req = search("uid=bob,ou=people,dc=example,dc=com", Scope::Base, present());
        assert_eq!(collect(&req, &cfg, &db()).len(), 1);
    }

    #[test]
    fn excluded_users_removed_from_memberuid() {
        let cfg = cfg_with(|c| c.uid_ranges = vec![1001..=1001]); // alice only
        let req = search("cn=staff,ou=groups,dc=example,dc=com", Scope::Base, present());
        let entries = collect(&req, &cfg, &db());
        assert_eq!(attr_values(&entries[0], "memberUid"), vec!["alice"]);
        // And via enumeration.
        let req = search("ou=groups,dc=example,dc=com", Scope::OneLevel, present());
        let entries = collect(&req, &cfg, &db());
        let staff = entries.iter().find(|e| e.dn.starts_with("cn=staff")).unwrap();
        assert_eq!(attr_values(staff, "memberUid"), vec!["alice"]);
    }

    // GID range filtering

    #[test]
    fn gid_range_no_ranges_permits_all_groups() {
        let req = search("ou=groups,dc=example,dc=com", Scope::OneLevel, present());
        assert_eq!(collect(&req, &cfg(), &db()).len(), groups().len());
    }

    #[test]
    fn gid_range_restricts_groups() {
        // staff=200, wheel=201, empty=202; primary gids 1001,1002 have no group.
        let cfg = cfg_with(|c| c.gid_ranges = vec![202..=202]);
        let req = search("ou=groups,dc=example,dc=com", Scope::OneLevel, present());
        let dns = dn_set(&collect(&req, &cfg, &db()));
        assert_eq!(dns, vec!["cn=empty,ou=groups,dc=example,dc=com"]);
    }

    #[test]
    fn primary_gid_always_visible() {
        let mut d = db();
        d.groups.push(group("alicegroup", 1001, &[]));
        let cfg = cfg_with(|c| c.gid_ranges = vec![200..=200]); // only staff
        let req = search("ou=groups,dc=example,dc=com", Scope::OneLevel, present());
        let dns = dn_set(&collect(&req, &cfg, &d));
        assert_eq!(dns, vec![
            "cn=alicegroup,ou=groups,dc=example,dc=com",
            "cn=staff,ou=groups,dc=example,dc=com",
        ]);
        // Leaf lookup honours the same rule.
        let req = search("cn=alicegroup,ou=groups,dc=example,dc=com", Scope::Base, present());
        assert_eq!(collect(&req, &cfg, &d).len(), 1);
        let req = search("cn=wheel,ou=groups,dc=example,dc=com", Scope::Base, present());
        assert!(collect(&req, &cfg, &d).is_empty());
    }

    // Attribute selection

    #[test]
    fn select_all_when_empty_requested() {
        let entry = user_entry(&users()[0], &cfg());
        let selected = select_attributes(&entry, &[]);
        assert_eq!(selected.attributes.len(), entry.attributes.len());
    }

    #[test]
    fn select_specific_attributes() {
        let entry = user_entry(&users()[0], &cfg());
        let requested: Vec<String> = vec!["uid".into(), "uidNumber".into()];
        let selected = select_attributes(&entry, &requested);
        assert_eq!(selected.attributes.len(), 2);
        assert!(attr_values(&selected, "uid").contains(&"alice"));
        assert!(attr_values(&selected, "cn").is_empty());
    }

    #[test]
    fn select_star_returns_all() {
        let entry = user_entry(&users()[0], &cfg());
        let selected = select_attributes(&entry, &["*".into()]);
        assert_eq!(selected.attributes.len(), entry.attributes.len());
    }

    #[test]
    fn select_no_attributes_marker() {
        let entry = user_entry(&users()[0], &cfg());
        let selected = select_attributes(&entry, &["1.1".into()]);
        assert!(selected.attributes.is_empty());
        assert_eq!(selected.dn, entry.dn);
    }

    #[test]
    fn select_attributes_case_insensitive_names() {
        let entry = user_entry(&users()[0], &cfg());
        let selected = select_attributes(&entry, &["UID".into(), "CN".into()]);
        assert_eq!(selected.attributes.len(), 2);
        assert!(attr_values(&selected, "uid").contains(&"alice"));
        assert!(attr_values(&selected, "cn").contains(&"Alice Smith"));
    }

    // User attribute extension

    fn alice() -> User {
        users()[0].clone()
    }

    fn cfg_with_user_attrs(
        attrs: Vec<(String, AttrValue)>,
        overrides: HashMap<String, HashMap<String, String>>,
    ) -> Config {
        cfg_with(|c| {
            c.user_attributes = attrs;
            c.user_overrides = overrides;
        })
    }

    #[test]
    fn template_attr_expands_uid() {
        let cfg = cfg_with_user_attrs(
            vec![("mail".into(), AttrValue::Template("{uid}@example.com".into()))],
            HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "mail"), vec!["alice@example.com"]);
    }

    #[test]
    fn fixed_attr_added() {
        let cfg = cfg_with_user_attrs(
            vec![("department".into(), AttrValue::Fixed("Engineering".into()))],
            HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "department"), vec!["Engineering"]);
    }

    #[test]
    fn user_attr_overrides_builtin() {
        let cfg = cfg_with_user_attrs(
            vec![("loginShell".into(), AttrValue::Fixed("/bin/zsh".into()))],
            HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "loginShell"), vec!["/bin/zsh"]);
    }

    #[test]
    fn per_user_override_takes_precedence() {
        let overrides = HashMap::from([(
            "alice".to_string(),
            HashMap::from([("mail".to_string(), "alice@external.com".to_string())]),
        )]);
        let cfg = cfg_with_user_attrs(
            vec![("mail".into(), AttrValue::Template("{uid}@example.com".into()))],
            overrides,
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "mail"), vec!["alice@external.com"]);
    }

    #[test]
    fn per_user_override_without_general_rule() {
        let overrides = HashMap::from([(
            "alice".to_string(),
            HashMap::from([("title".to_string(), "Director".to_string())]),
        )]);
        let cfg = cfg_with_user_attrs(vec![], overrides);
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "title"), vec!["Director"]);
    }

    #[test]
    fn override_for_other_user_not_applied() {
        let overrides = HashMap::from([(
            "bob".to_string(),
            HashMap::from([("mail".to_string(), "bob@other.com".to_string())]),
        )]);
        let cfg = cfg_with_user_attrs(
            vec![("mail".into(), AttrValue::Template("{uid}@example.com".into()))],
            overrides,
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "mail"), vec!["alice@example.com"]);
    }

    // bind_username

    #[test]
    fn bind_username_accepts_served_dn_and_bare_name() {
        let cfg = cfg();
        assert_eq!(
            bind_username("uid=alice,ou=people,dc=example,dc=com", &cfg),
            Some("alice".into())
        );
        assert_eq!(
            bind_username("UID=alice , OU=People, DC=Example,DC=com", &cfg),
            Some("alice".into())
        );
        assert_eq!(bind_username("alice", &cfg), Some("alice".into()));
    }

    #[test]
    fn bind_username_rejects_foreign_or_malformed_dns() {
        let cfg = cfg();
        for dn in [
            "uid=alice,dc=evil",
            "uid=alice,cn=x,ou=people,dc=example,dc=com",
            "cn=alice,ou=people,dc=example,dc=com",
            "uid=alice",
            "alice,bob",
            "uid=ali ce,ou=people,dc=example,dc=com",
            "uid=,ou=people,dc=example,dc=com",
            "",
        ] {
            assert_eq!(bind_username(dn, &cfg), None, "{dn:?}");
        }
    }

    // Wire reading

    async fn read_from(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        read_ldap_message(&mut cursor).await.map(|z| z.to_vec())
    }

    #[tokio::test]
    async fn read_message_short_and_long_forms() {
        let short = [0x30, 0x03, 0x02, 0x01, 0x07, 0xff];
        assert_eq!(read_from(&short).await.unwrap(), &short[..5]);
        let mut long = vec![0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x07];
        assert_eq!(read_from(&long).await.unwrap(), long);
        long.pop();
        assert_eq!(
            read_from(&long).await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn read_message_rejects_bad_length_forms() {
        for bad in [
            vec![0x30, 0x80, 0x00, 0x00],             // indefinite
            vec![0x30, 0x85, 0, 0, 0, 0, 1, 0],       // five octets
            vec![0x30, 0x83, 0xff, 0xff, 0xff],       // over MAX_MESSAGE_BYTES
        ] {
            assert_eq!(
                read_from(&bad).await.unwrap_err().kind(),
                std::io::ErrorKind::InvalidData,
                "{bad:?}"
            );
        }
    }

    // Connection-level behaviour, driven over an in-memory duplex pipe.

    async fn client_read<S: AsyncRead + Unpin>(s: &mut S) -> (i64, u8, Vec<u8>) {
        let bytes = read_ldap_message(s).await.expect("response");
        let (seq, _) = ber::expect_tag(&bytes, ber::TAG_SEQUENCE).unwrap();
        let (id, rest) = ber::decode_integer(seq).unwrap();
        let (tag, value, _) = ber::parse_tlv(rest).unwrap();
        (id, tag, value.to_vec())
    }

    fn result_code(op_value: &[u8]) -> u32 {
        ber::decode_enumerated(op_value).unwrap().0
    }

    fn envelope(id: i64, op: Vec<u8>) -> Vec<u8> {
        let mut content = ber::encode_integer(id);
        content.extend(op);
        ber::encode_tlv(ber::TAG_SEQUENCE, &content)
    }

    fn bind_msg(id: i64, name: &str, auth: Vec<u8>) -> Vec<u8> {
        let mut body = ber::encode_integer(3);
        body.extend(ber::encode_string(name));
        body.extend(auth);
        envelope(id, ber::encode_tlv(0x60, &body))
    }

    fn search_msg(id: i64, base: &str, scope: u32, size_limit: i64, types_only: bool) -> Vec<u8> {
        let mut body = ber::encode_string(base);
        body.extend(ber::encode_enumerated(scope));
        body.extend(ber::encode_enumerated(0));
        body.extend(ber::encode_integer(size_limit));
        body.extend(ber::encode_integer(0));
        body.extend(ber::encode_tlv(ber::TAG_BOOLEAN, &[if types_only { 0xff } else { 0 }]));
        body.extend(ber::encode_tlv(0x87, b"objectClass"));
        body.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &[]));
        envelope(id, ber::encode_tlv(0x63, &body))
    }

    /// Start a handler on one end of a duplex pipe; return the client end
    /// and the handler task.
    fn connect(cfg: Config) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let cfg = Arc::new(cfg);
        let dir: SharedDirectory = Arc::new(db());
        let task = tokio::spawn(async move {
            handle_connection(server, cfg, dir, "test").await
        });
        (client, task)
    }

    /// Read `SearchResultEntry`s until the `SearchResultDone`; return the
    /// entries' raw op values and the done result code.
    async fn read_search<S: AsyncRead + Unpin>(s: &mut S) -> (Vec<Vec<u8>>, u32) {
        let mut entries = Vec::new();
        loop {
            let (_, tag, value) = client_read(s).await;
            match tag {
                0x64 => entries.push(value),
                0x65 => return (entries, result_code(&value)),
                t => panic!("unexpected tag {t:#x}"),
            }
        }
    }

    #[tokio::test]
    async fn anonymous_bind_then_search_and_unbind() {
        let (mut c, task) = connect(cfg());
        c.write_all(&bind_msg(1, "", ber::encode_tlv(0x80, b""))).await.unwrap();
        let (id, tag, value) = client_read(&mut c).await;
        assert_eq!((id, tag, result_code(&value)), (1, 0x61, ldap::SUCCESS));

        c.write_all(&search_msg(2, "ou=people,dc=example,dc=com", 1, 0, false)).await.unwrap();
        let (entries, code) = read_search(&mut c).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(code, ldap::SUCCESS);

        c.write_all(&envelope(3, ber::encode_tlv(0x42, &[]))).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn size_limit_and_types_only_are_honoured() {
        let (mut c, _task) = connect(cfg());
        c.write_all(&search_msg(1, "ou=people,dc=example,dc=com", 1, 1, true)).await.unwrap();
        let (entries, code) = read_search(&mut c).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(code, ldap::SIZE_LIMIT_EXCEEDED);
        // typesOnly: every attribute carries an empty SET.
        let (_, rest) = ber::decode_string(&entries[0]).unwrap();
        let (attr_list, _) = ber::expect_tag(rest, ber::TAG_SEQUENCE).unwrap();
        let mut r = attr_list;
        let mut seen = 0;
        while !r.is_empty() {
            let (a, next) = ber::expect_tag(r, ber::TAG_SEQUENCE).unwrap();
            let (_, set) = ber::decode_string(a).unwrap();
            let (set, _) = ber::expect_tag(set, ber::TAG_SET).unwrap();
            assert!(set.is_empty());
            seen += 1;
            r = next;
        }
        assert!(seen > 0);

        // A limit equal to the result count is not "exceeded".
        c.write_all(&search_msg(2, "ou=people,dc=example,dc=com", 1, 2, false)).await.unwrap();
        let (entries, code) = read_search(&mut c).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(code, ldap::SUCCESS);
    }

    #[tokio::test]
    async fn unsupported_operation_gets_unwilling_and_connection_survives() {
        let (mut c, _task) = connect(cfg());
        // AddRequest with arbitrary body.
        c.write_all(&envelope(4, ber::encode_tlv(0x68, b"\x04\x00\x30\x00"))).await.unwrap();
        let (id, tag, value) = client_read(&mut c).await;
        assert_eq!((id, tag, result_code(&value)), (4, 0x69, ldap::UNWILLING_TO_PERFORM));
        // ExtendedRequest (StartTLS) maps to ExtendedResponse.
        c.write_all(&envelope(5, ber::encode_tlv(0x77, b"\x80\x00"))).await.unwrap();
        let (id, tag, value) = client_read(&mut c).await;
        assert_eq!((id, tag, result_code(&value)), (5, 0x78, ldap::UNWILLING_TO_PERFORM));
        // Still serving.
        c.write_all(&search_msg(6, "", 0, 0, false)).await.unwrap();
        let (entries, code) = read_search(&mut c).await;
        assert_eq!((entries.len(), code), (1, ldap::SUCCESS));
    }

    #[tokio::test]
    async fn sasl_bind_is_refused_with_auth_method_not_supported() {
        let (mut c, _task) = connect(cfg());
        let sasl = ber::encode_tlv(0xa3, &ber::encode_string("EXTERNAL"));
        c.write_all(&bind_msg(1, "", sasl)).await.unwrap();
        let (_, tag, value) = client_read(&mut c).await;
        assert_eq!((tag, result_code(&value)), (0x61, ldap::AUTH_METHOD_NOT_SUPPORTED));
    }

    #[tokio::test]
    async fn bind_with_foreign_dn_is_invalid_credentials() {
        let (mut c, _task) = connect(cfg());
        c.write_all(&bind_msg(1, "uid=alice,dc=evil", ber::encode_tlv(0x80, b"pw"))).await.unwrap();
        let (_, tag, value) = client_read(&mut c).await;
        assert_eq!((tag, result_code(&value)), (0x61, ldap::INVALID_CREDENTIALS));
    }

    #[tokio::test]
    async fn require_bind_blocks_anonymous_search() {
        let (mut c, _task) = connect(cfg_with(|c| c.require_bind = vec!["svc".into()]));
        c.write_all(&search_msg(1, "", 0, 0, false)).await.unwrap();
        let (entries, code) = read_search(&mut c).await;
        assert!(entries.is_empty());
        assert_eq!(code, ldap::INSUFFICIENT_ACCESS_RIGHTS);
    }

    #[tokio::test]
    async fn malformed_message_gets_notice_of_disconnection() {
        let (mut c, task) = connect(cfg());
        // Well-framed SEQUENCE whose operation tag is unknown.
        c.write_all(&envelope(7, ber::encode_tlv(0x7e, b""))).await.unwrap();
        let (id, tag, value) = client_read(&mut c).await;
        assert_eq!((id, tag, result_code(&value)), (0, 0x78, ldap::PROTOCOL_ERROR));
        task.await.unwrap().unwrap();
        // Bad framing (indefinite length) also disconnects.
        let (mut c, task) = connect(cfg());
        c.write_all(&[0x30, 0x80]).await.unwrap();
        let (id, tag, _) = client_read(&mut c).await;
        assert_eq!((id, tag), (0, 0x78));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_connection_is_closed() {
        let cfg = cfg_with(|c| c.idle_timeout = Some(std::time::Duration::from_millis(50)));
        let (_c, task) = connect(cfg);
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        res.expect("handler returned before test timeout").unwrap().unwrap();
    }
}
