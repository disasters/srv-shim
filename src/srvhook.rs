extern crate libc;
extern crate plumber;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int, size_t, ssize_t};
use std::collections::{BTreeMap};
use std::ffi::{CStr};
use std::mem;
use std::str::from_utf8;
use std::sync::{RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};

use plumber::dynamic::dlsym_next;
use plumber::util::{sockaddr_to_port_ip,port_ip_to_sa_data};
use plumber::util::{ip_to_usize,usize_to_ip};
use plumber::dns::srv_mapper;
use plumber::hooks::Hook;

pub struct SRVHook {
    max_ip: AtomicUsize,
    magic_ip_to_host: RwLock<BTreeMap<[u8;4], String>>,
    host_to_magic_ip: RwLock<BTreeMap<String, [u8;4]>>,
    real_connect:
        unsafe extern "C" fn(c_int, *const sockaddr,
                             socklen_t) -> c_int,
    real_getaddrinfo:
        unsafe extern "C" fn(node: *const c_char,
                              service: *const c_char,
                              hints: *const addrinfo,
                              res: *const *const addrinfo) -> c_int,
    real_sendto:
        unsafe extern "C" fn(socket: c_int, msg: *const c_char,
                             msglen: size_t, flags: c_int,
                             dest_addr: *mut sockaddr) -> ssize_t,
}

impl SRVHook {
    pub unsafe fn new() -> SRVHook {
        SRVHook{
            // 250/8 is currently reserved for future use by IANA, so
            // it should be a safe choice.
            max_ip: AtomicUsize::new(ip_to_usize([250,0,0,0])),
            magic_ip_to_host: RwLock::new(BTreeMap::new()),
            host_to_magic_ip: RwLock::new(BTreeMap::new()),
            real_getaddrinfo:
                mem::transmute(dlsym_next("getaddrinfo\0").unwrap()),
            real_connect:
                mem::transmute(dlsym_next("connect\0").unwrap()),
            real_sendto:
                mem::transmute(dlsym_next("sendto\0").unwrap()),
        }
    }

    pub fn set_sockaddr(&self, address: *mut sockaddr) {
        let (_, ip) = sockaddr_to_port_ip(address);
        let iph = self.magic_ip_to_host.read().unwrap();
        iph.get(&ip).map(|h| {
            srv_mapper(h).map( |(new_port, new_ip)| {
                unsafe {
                    // only override host and IP for AF_INET
                    if (*address).sa_family == 2 {
                        (*address).sa_data =
                            port_ip_to_sa_data(new_port, new_ip);
                    }
                }
            }).or_else(|e| {
                println!("srv-shim: failed to look up SRV record for {}: {}", h, e);
                Err(e)
            });
        });
    }

    fn next_ip(&self) -> [u8;4] {
        let id = self.max_ip.fetch_add(1, Ordering::Relaxed);
        usize_to_ip(id)
    }
}

impl Hook for SRVHook {
    fn connect(&self, socket: c_int, address: *mut sockaddr,
                   len: socklen_t) -> c_int {
        self.set_sockaddr(address);
        unsafe {
            (self.real_connect)(socket, address, len)
        }
    }

    fn sendto(&self, socket: c_int, msg: *const c_char, msglen: size_t,
                         flags: c_int, dest_addr: *mut sockaddr) -> ssize_t {
        self.set_sockaddr(dest_addr);
        unsafe {
            (self.real_sendto)(socket, msg, msglen, flags, dest_addr)
        }
    }

    fn getaddrinfo(&self, node: *const c_char, service: *const c_char,
                   hints: *const addrinfo, res: *mut *const addrinfo) -> c_int {
        let c_str = unsafe { CStr::from_ptr(node) };
        let node_str: String = from_utf8(c_str.to_bytes()).unwrap().to_owned();
        // Trigger on possible SRV records.
        if node_str.starts_with("_") {
            let mut hip = self.host_to_magic_ip.write().unwrap();
            let ip = match hip.get(&node_str) {
                Some(ip) => *ip,
                None => {
                    let ip = self.next_ip();
                    let mut iph = self.magic_ip_to_host.write().unwrap();
                    iph.insert(ip, node_str.clone());
                    ip
                },
            };
            hip.insert(node_str, ip);
            unsafe {
                let sa_buf: *mut sockaddr =
                    mem::transmute(
                        libc::malloc(mem::size_of::<sockaddr>() as size_t)
                    );
                *sa_buf = sockaddr{
                    sa_family: 2,
                    sa_data: port_ip_to_sa_data(8080, ip),
                };

                let ai_buf: *mut addrinfo =
                    mem::transmute(
                        libc::malloc(mem::size_of::<addrinfo>() as size_t)
                    );
                *ai_buf = addrinfo{
                    ai_flags: 0,
                    ai_family: 2,
                    ai_socktype: 1,
                    ai_protocol: 6,
                    ai_addrlen: 16,
                    ai_addr: sa_buf,
                    ai_canonname: 0 as *mut i8,
                    ai_next: 0 as *mut addrinfo,
                };
                *res = ai_buf;
            }
            0
        } else {
            unsafe {
                (self.real_getaddrinfo)(node, service, hints, res)
            }
        }
    }
}
