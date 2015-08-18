# srv-shim
SRV record support for legacy systems.  Built on top of [plumber](https://github.com/the-tetanus-clinic/plumber), part of the [discotech](https://github.com/the-tetanus-clinic/discotech) suite.

It works by intercepting calls to getaddrinfo, which would normally fail due to reliance on A/AAAA records, and using SRV instead.

#### Compile-Time Prerequisites
1. [Rust](https://www.rust-lang.org/install.html) (stable recommended but not required)

#### Building
```
cargo build
```

Now, `target/debug/libsrvshim.so` should exist.

#### Usage
Linux/FreeBSD:
```
LD_PRELOAD=target/debug/libplumber.so \
curl _my-service._tcp.domain
```
You may also create an entry in `/etc/ld.so.conf` to cause it to be loaded in all processes on the system.

OSX:
```
DYLD_INSERT_LIBRARIES=/abs/path/to/libplumber.so \
DYLD_FORCE_FLAT_NAMESPACE=YES \
curl _my-service._tcp.domain
```
