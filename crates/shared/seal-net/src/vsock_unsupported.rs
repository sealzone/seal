//! `vsock` off Linux: the same names, and every call fails with `ErrorKind::Unsupported`, so
//! crates that name vsock build everywhere and run only where Nitro does.

use std::io;
use std::time::Duration;

use tokio::net::TcpStream;

pub const CID_ANY: u32 = u32::MAX;
pub const CID_LOCAL: u32 = 1;
pub const PORT_ANY: u32 = u32::MAX;

fn unsupported_here() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "vsock is Linux only")
}

pub async fn connect(_cid: u32, _port: u32, _timeout: Duration) -> io::Result<TcpStream> {
    Err(unsupported_here())
}

/// Never made off Linux.
pub struct VsockListener(std::convert::Infallible);

impl VsockListener {
    pub fn bind(_cid: u32, _port: u32) -> io::Result<Self> {
        Err(unsupported_here())
    }

    pub fn port(&self) -> u32 {
        match self.0 {}
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, u32)> {
        match self.0 {}
    }
}

pub fn unsupported(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::Unsupported
}
