//! PAM-based authentication for LDAP simple binds.

const PAM_SERVICE: &str = "pwldapd";

/// Longest user name we will hand to PAM. Linux limits names to 32
/// characters, but NSS backends may allow more; 256 is generous.
const MAX_USERNAME_LEN: usize = 256;

/// Warn at startup if the PAM service file is missing.
/// Without it PAM falls back to /etc/pam.d/other, which typically denies
/// all access, causing every bind to silently fail.
pub fn check_pam_service() {
    let path = format!("/etc/pam.d/{PAM_SERVICE}");
    if !std::path::Path::new(&path).exists() {
        tracing::warn!(
            "{path} not found: bind authentication will fail. \
             Create {path} before clients attempt to authenticate."
        );
    }
}

/// Reject names that are not plausible account names before they reach
/// PAM. PAM modules log the name verbatim, so control characters would
/// permit log injection, and `:` cannot appear in a passwd entry.
pub fn is_valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_USERNAME_LEN
        && !name.starts_with('-')
        && name.bytes().all(|b| {
            b.is_ascii_graphic() && b != b':' && b != b'/'
        })
}

pub fn authenticate(username: &str, password: &str) -> bool {
    if password.is_empty() || !is_valid_username(username) {
        return false;
    }
    match pam::Authenticator::with_password(PAM_SERVICE) {
        Ok(mut auth) => {
            auth.get_handler().set_credentials(username, password);
            match auth.authenticate() {
                Ok(()) => {
                    tracing::debug!("PAM authenticated '{username}'");
                    true
                }
                Err(e) => {
                    tracing::debug!("PAM rejected '{username}': {e}");
                    false
                }
            }
        }
        Err(e) => {
            tracing::error!("PAM init failed: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        for name in ["alice", "svc_ldap", "bob.jones", "user-1", "u$", "A"] {
            assert!(is_valid_username(name), "{name:?}");
        }
    }

    #[test]
    fn invalid_usernames() {
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        for name in [
            "", " ", "alice bob", "ali\nce", "ali\tce", "a:b", "a/b",
            "-flag", "\u{e9}", long.as_str(),
        ] {
            assert!(!is_valid_username(name), "{name:?}");
        }
    }

    #[test]
    fn authenticate_rejects_bad_input_without_pam() {
        assert!(!authenticate("alice", ""));
        assert!(!authenticate("", "secret"));
        assert!(!authenticate("ali\nce", "secret"));
    }
}
