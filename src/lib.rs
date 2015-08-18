#[macro_use] extern crate lazy_static;
#[macro_use] extern crate plumber;
pub use srvhook::SRVHook;
pub mod srvhook;

extern crate libc;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int, size_t, ssize_t};
use plumber::hooks::Hook;

set_hook!(SRVHook : SRVHook::new());
