/// POSIX password and group database lookups via libc.
use std::ffi::{CStr, CString};
use std::sync::Mutex;

// setpwent/getpwent and setgrent/getgrent use global state
// and are not thread-safe.
static DB_LOCK: Mutex<()> = Mutex::new(());

/// Largest buffer we will offer to the reentrant lookup functions before
/// giving up on an entry.
const MAX_LOOKUP_BUF: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home_dir: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// Source of account data. The system implementation reads the NSS
/// databases; tests supply an in-memory one.
pub trait Directory {
    fn all_users(&self) -> Vec<User>;
    fn all_groups(&self) -> Vec<Group>;
    fn user_by_name(&self, name: &str) -> Option<User>;
    fn group_by_name(&self, name: &str) -> Option<Group>;
}

/// The live NSS user and group databases.
pub struct SystemDirectory;

impl Directory for SystemDirectory {
    fn all_users(&self) -> Vec<User> { get_all_users() }
    fn all_groups(&self) -> Vec<Group> { get_all_groups() }
    fn user_by_name(&self, name: &str) -> Option<User> {
        get_user_by_name(name)
    }
    fn group_by_name(&self, name: &str) -> Option<Group> {
        get_group_by_name(name)
    }
}

/// Take the enumeration lock, recovering from poisoning: the guarded state
/// is only the libc cursor, which set*ent() resets anyway.
fn lock_db() -> std::sync::MutexGuard<'static, ()> {
    DB_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn get_user_by_name(name: &str) -> Option<User> {
    let cname = CString::new(name).ok()?;
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0u8; 1024];
    loop {
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                None
            } else {
                Some(unsafe { passwd_to_user(&*result) })
            };
        }
        if rc == libc::ERANGE && buf.len() < MAX_LOOKUP_BUF {
            buf.resize(buf.len() * 2, 0);
        } else {
            return None;
        }
    }
}

pub fn get_group_by_name(name: &str) -> Option<Group> {
    let cname = CString::new(name).ok()?;
    let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
    let mut buf = vec![0u8; 1024];
    loop {
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                None
            } else {
                Some(unsafe { group_to_group(&*result) })
            };
        }
        if rc == libc::ERANGE && buf.len() < MAX_LOOKUP_BUF {
            buf.resize(buf.len() * 2, 0);
        } else {
            return None;
        }
    }
}

pub fn get_all_users() -> Vec<User> {
    let _guard = lock_db();
    let mut users = Vec::new();
    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() { break; }
            users.push(passwd_to_user(&*pw));
        }
        libc::endpwent();
    }
    users
}

pub fn get_all_groups() -> Vec<Group> {
    let _guard = lock_db();
    let mut groups = Vec::new();
    unsafe {
        libc::setgrent();
        loop {
            let gr = libc::getgrent();
            if gr.is_null() { break; }
            groups.push(group_to_group(&*gr));
        }
        libc::endgrent();
    }
    groups
}

unsafe fn passwd_to_user(pw: &libc::passwd) -> User {
    User {
        name: unsafe { cstr(pw.pw_name) },
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        gecos: unsafe { cstr(pw.pw_gecos) },
        home_dir: unsafe { cstr(pw.pw_dir) },
        shell: unsafe { cstr(pw.pw_shell) },
    }
}

unsafe fn group_to_group(gr: &libc::group) -> Group {
    let mut members = Vec::new();
    if !gr.gr_mem.is_null() {
        let mut i = 0;
        loop {
            let ptr = unsafe { *gr.gr_mem.add(i) };
            if ptr.is_null() { break; }
            members.push(unsafe { cstr(ptr) });
            i += 1;
        }
    }
    Group {
        name: unsafe { cstr(gr.gr_name) },
        gid: gr.gr_gid,
        members,
    }
}

unsafe fn cstr(ptr: *const libc::c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // root exists on every POSIX system the tests can run on.

    #[test]
    fn root_user_lookup() {
        let root = get_user_by_name("root").expect("root user");
        assert_eq!(root.uid, 0);
        assert_eq!(root.name, "root");
    }

    #[test]
    fn root_group_lookup() {
        let root = get_group_by_name("root").expect("root group");
        assert_eq!(root.gid, 0);
    }

    #[test]
    fn missing_entries_are_none() {
        assert!(get_user_by_name("no-such-user-pwldapd").is_none());
        assert!(get_group_by_name("no-such-group-pwldapd").is_none());
        // Embedded NUL cannot be passed to libc.
        assert!(get_user_by_name("ro\0ot").is_none());
    }

    #[test]
    fn enumeration_includes_root() {
        assert!(get_all_users().iter().any(|u| u.uid == 0));
        assert!(get_all_groups().iter().any(|g| g.gid == 0));
    }
}
