//! Fixed, direct request to an IP literal or a resolved hostname. Completion is
//! never outcome proof.

use std::env;
use std::ffi::OsString;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

struct Input {
    host: String,
    port: u16,
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

// Matches PERL_PROBE's and the Python-side validate_receiver_url()'s own
// `[a-zA-Z0-9:][a-zA-Z0-9.:-]{0,252}` character class exactly: an IP literal
// (bracket-free) or a DNS name, never a scoped/bracketed address, a name with
// other punctuation, or anything containing header-injection characters.
fn valid_host(host: &str) -> bool {
    let bytes = host.as_bytes();
    (1..=253).contains(&bytes.len())
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b':')
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'))
}

fn parse(args: &[OsString]) -> Option<Input> {
    if args.len() != 4 {
        return None;
    }
    let host = args[0].to_str()?;
    if !valid_host(host) {
        return None;
    }
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
        host: host.to_string(),
        port,
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
    // A bare colon only ever appears in an IPv6 literal (valid_host's character
    // class has no other use for it), matching PERL_PROBE's own authority rule.
    let authority = if input.host.contains(':') {
        format!("[{}]:{}", input.host, input.port)
    } else {
        format!("{}:{}", input.host, input.port)
    };
    format!(
        "GET /probe HTTP/1.1\r\nHost: {}\r\nX-Gate-Attempt: {}\r\nConnection: close\r\n\r\n",
        authority, input.attempt
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

// A name that does not resolve, a resolver that never answers and a candidate
// that refuses the connection are the same outcome from here: the configured
// receiver could not be reached. None of that is a runtime/implementation bug,
// so it always completes the attempt, exactly like a direct connection failure.
fn resolve(host: &str, port: u16, deadline: Instant) -> Result<SocketAddr, ProbeError> {
    let budget = network_result(remaining(deadline))?;
    let (sender, receiver) = mpsc::channel();
    let owned_host = host.to_string();
    // The lookup has no cancellation point; an unanswering resolver leaves this
    // thread blocked past the deadline. The process exits without waiting for
    // it regardless, since only the main thread's return value matters.
    thread::spawn(move || {
        let _ = sender.send((owned_host.as_str(), port).to_socket_addrs());
    });
    match receiver.recv_timeout(budget) {
        Ok(Ok(mut addresses)) => addresses.next().ok_or(ProbeError::Network),
        Ok(Err(_)) | Err(_) => Err(ProbeError::Network),
    }
}

fn probe(input: &Input) -> Result<(), ProbeError> {
    let deadline = Instant::now() + Duration::from_secs(input.seconds);
    let address = resolve(&input.host, input.port, deadline)?;
    let mut stream = network_result(TcpStream::connect_timeout(
        &address,
        network_result(remaining(deadline))?,
    ))?;
    exchange(&mut stream, request(input).as_bytes(), deadline)
    // stream drops here, including on errors. The resolver thread, if still
    // blocked, is abandoned when the process exits.
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).take(5).collect();
    if args.len() == 1 && args[0] == "--version" {
        if writeln!(
            io::stdout().lock(),
            "gate-http-probe {} agent-boundary-gate/http-probe/1.0 experimental-dns",
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
            ["", "80", "probe-test", "1"],
            ["::1%zone", "80", "probe-test", "1"],
            ["[::1]", "80", "probe-test", "1"],
            ["host name", "80", "probe-test", "1"],
            ["host_name", "80", "probe-test", "1"],
            ["host\r\nInjected:1", "80", "probe-test", "1"],
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
    fn valid_hostnames_and_ip_literals_accepted() {
        for host in [
            "localhost",
            "example.com",
            "a",
            "127.0.0.1",
            "::1",
            "a1-b.c",
        ] {
            assert!(input(&[host, "80", "probe-test", "1"]).is_some(), "{host}");
        }
        // The first character and overall length bounds match PERL_PROBE's regex exactly.
        assert!(input(&[&"a".repeat(253), "80", "probe-test", "1"]).is_some());
        assert!(input(&[&"a".repeat(254), "80", "probe-test", "1"]).is_none());
        assert!(input(&[".leading-dot", "80", "probe-test", "1"]).is_none());
        assert!(input(&["-leading-hyphen", "80", "probe-test", "1"]).is_none());
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
