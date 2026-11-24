//! Тонкая обёртка над `rustls::ServerConnection` + `TcpStream` с таймаутами.

use std::io::{self, Read, Write};
use std::net::{Shutdown as SocketShutdown, TcpStream};
use std::time::{Duration, Instant};

use rustls::ServerConnection;

use crate::error::Error;
use crate::tls::TlsConfig;

/// Установленное TLS-соединение с проверенным ALPN.
pub(crate) struct TlsStream {
    connection: ServerConnection,
    socket: TcpStream,
}

impl TlsStream {
    /// Выполняет рукопожатие с общим дедлайном и проверяет ALPN.
    pub(crate) fn accept(
        tls: &TlsConfig,
        mut socket: TcpStream,
        handshake_timeout: Duration,
    ) -> Result<Self, Error> {
        if handshake_timeout.is_zero() {
            return Err(Error::InvalidConfig("handshake timeout must be positive"));
        }
        socket.set_nodelay(true)?;
        socket.set_nonblocking(false)?;
        let deadline = Instant::now()
            .checked_add(handshake_timeout)
            .ok_or(Error::InvalidConfig("handshake timeout is too large"))?;
        let mut connection = ServerConnection::new(tls.server_config())?;
        while connection.is_handshaking() {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::HandshakeTimeout);
            }
            let remaining = deadline.saturating_duration_since(now);
            socket.set_read_timeout(Some(remaining))?;
            socket.set_write_timeout(Some(remaining))?;
            match connection.complete_io(&mut socket) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(Error::HandshakeTimeout);
                    }
                }
                Err(error) => return Err(Error::Io(error)),
            }
        }
        tls.verify_alpn(&connection)?;
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
        Ok(Self { connection, socket })
    }

    pub(crate) fn set_idle_timeout(&self, timeout: Duration) -> Result<(), Error> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfig("idle timeout must be positive"));
        }
        self.socket.set_read_timeout(Some(timeout))?;
        self.socket.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    /// Читает прикладные байты; `Ok(0)` — чистое закрытие TLS.
    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        loop {
            match self.connection.reader().read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(Error::Io(error)),
            }
            let read = self.connection.read_tls(&mut self.socket)?;
            if read == 0 {
                return Err(Error::Closed);
            }
            self.connection.process_new_packets()?;
        }
    }

    pub(crate) fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), Error> {
        let mut offset = 0;
        while offset < buffer.len() {
            let rest = buffer
                .get_mut(offset..)
                .ok_or_else(|| Error::Http("read offset out of bounds".to_owned()))?;
            match self.read(rest)? {
                0 => return Err(Error::Closed),
                read => offset += read,
            }
        }
        Ok(())
    }

    pub(crate) fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        self.connection.writer().write_all(data)?;
        self.flush()
    }

    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) => {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS write returned zero bytes",
                    )));
                }
                Ok(_) => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) {
        self.connection.send_close_notify();
        let _ = self.flush();
        let _ = self.socket.shutdown(SocketShutdown::Both);
    }
}
