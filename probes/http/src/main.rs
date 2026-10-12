//! Fixed, direct IP-literal request. Completion is never outcome proof.

use std::env;
use std::ffi::OsString;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::{Duration, Instant};

struct Input {
    address: SocketAddr,
    attempt: String,
    seconds: u64,
}

enum ProbeError {
    Network,
    Runtime,
}

fn network_result<T>(result: io::Result<T>) -> Result<T, ProbeError> {
    result.map_err(|error| {
        if network_failure(error.kind()) {
            ProbeError::Network
        } else {
            ProbeError::Runtime
        }
    })
}

fn number(raw: &str, max_digits: usize, max: u64) -> Option<u64> {
    if raw.is_empty() || raw.len() > max_digits || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && *value <= max)
}

fn parse(args: &[OsString]) -> Option<Input> {
    if args.len() != 4 {
        return None;
    }
    let ip = args[0].to_str()?;
    if ip.len() > 45 {
        return None;
    }
    // IpAddr parsing performs no name resolution. Scoped/bracketed addresses
    // and names are rejected before creating any socket.
    let ip = ip.parse::<IpAddr>().ok()?;
    let port = number(args[1].to_str()?, 5, u16::MAX.into())? as u16;
    let attempt = args[2].to_str()?;
    if attempt.is_empty()
        || attempt.len() > 128
        || !attempt.as_bytes()[0].is_ascii_alphanumeric()
        || !attempt
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
    {
        return None;
    }
    let seconds = number(args[3].to_str()?, 2, 30)?;
    Some(Input {
        address: SocketAddr::new(ip, port),
        attempt: attempt.into(),
        seconds,
    })
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::from(ErrorKind::TimedOut))
}

fn request(input: &Input) -> String {
    // SocketAddr formats IPv6 authorities with brackets and IPv4 without them.
    format!(
        "GET /probe HTTP/1.1\r\nHost: {}\r\nX-Gate-Attempt: {}\r\nConnection: close\r\n\r\n",
        input.address, input.attempt
    )
}

fn network_failure(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::AddrNotAvailable
            | ErrorKind::PermissionDenied
    )
}

fn exchange(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<(), ProbeError> {
    let mut written = 0;
    while written < bytes.len() {
        stream
            .set_write_timeout(Some(network_result(remaining(deadline))?))
            .map_err(|_| ProbeError::Runtime)?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(ProbeError::Runtime),
            Ok(count) => written += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return network_result(Err(error)),
        }
    }
    // At most one response byte; no HTTP parsing or redirect/proxy support.
    loop {
        stream
            .set_read_timeout(Some(network_result(remaining(deadline))?))
            .map_err(|_| ProbeError::Runtime)?;
        match stream.read(&mut [0u8; 1]) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return network_result(Err(error)),
        }
    }
}

fn probe(input: &Input) -> Result<(), ProbeError> {
    let deadline = Instant::now() + Duration::from_secs(input.seconds);
    let mut stream = network_result(TcpStream::connect_timeout(
        &input.address,
        network_result(remaining(deadline))?,
    ))?;
    exchange(&mut stream, request(input).as_bytes(), deadline)
    // stream drops here, including on errors. No resolver threads/processes exist.
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).take(5).collect();
    if args.len() == 1 && args[0] == "--version" {
        if writeln!(
            io::stdout().lock(),
            "gate-http-probe {} agent-boundary-gate/http-probe/1.0 experimental-ip-literal",
            env!("CARGO_PKG_VERSION")
        )
        .is_err()
        {
            return ExitCode::from(2);
        }
        return ExitCode::SUCCESS;
    }
    let Some(input) = parse(&args) else {
        eprintln!("invalid-probe-input");
        return ExitCode::from(2);
    };
    if let Err(ProbeError::Runtime) = probe(&input) {
        eprintln!("probe-runtime-failed");
        return ExitCode::from(2);
    }
    // A broken stdout is a runtime failure, never a successful completion.
    if writeln!(
        io::stdout().lock(),
        "agent-boundary-gate-probe-complete:{}",
        input.attempt
    )
    .is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(args: &[&str]) -> Option<Input> {
        parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn ipv6_authority_and_fixed_request() {
        let value = input(&["::1", "8080", "probe-test", "1"]).unwrap();
        assert_eq!(
            request(&value),
            "GET /probe HTTP/1.1\r\nHost: [::1]:8080\r\nX-Gate-Attempt: probe-test\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn invalid_headers_and_bounds() {
        for args in [
            ["localhost", "80", "probe-test", "1"],
            ["::1%zone", "80", "probe-test", "1"],
            ["[::1]", "80", "probe-test", "1"],
            ["127.0.0.1", "65536", "probe-test", "1"],
            ["127.0.0.1", "80", "probe\r\nInjected:1", "1"],
            ["127.0.0.1", "80", "probe-test", "31"],
            ["127.0.0.1", "80", "probe-test", "0"],
            ["127.0.0.1", "80", "probe-test", "1.5"],
        ] {
            assert!(input(&args).is_none());
        }
    }

    #[test]
    fn expired_budget_cannot_restart() {
        assert_eq!(
            remaining(Instant::now() - Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn resource_faults_do_not_complete_as_network_rejections() {
        assert!(!network_failure(ErrorKind::OutOfMemory));
        assert!(!network_failure(ErrorKind::InvalidInput));
        assert!(!network_failure(ErrorKind::Other));
        assert!(network_failure(ErrorKind::PermissionDenied));
        assert!(network_failure(ErrorKind::ConnectionRefused));
    }
}
