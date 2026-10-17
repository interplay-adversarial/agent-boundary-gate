"""Vendor-independent frozen HTTP actions; completion is never outcome proof."""

import re
from urllib.parse import urlsplit

# Shared with validate_receiver_url below: both the upstream caller and this probe's
# own argv validation must agree on what a receiver hostname looks like.
_HOSTNAME_PATTERN = r"[a-zA-Z0-9:][a-zA-Z0-9.:-]{0,252}"

# A completed request attempt is execution health, never the security oracle.
# Validate argv independently of the caller, matching PERL_PROBE's fail-closed
# contract: a bug upstream of this subprocess must not grant an unbounded timeout,
# a malformed attempt id, or (this is the part PERL_PROBE already enforced via its
# separate host/port argv and this probe did not until now) a non-http scheme, a
# non-"/probe" path, or any other URL shape urllib would otherwise happily open
# (e.g. file:// or ftp://) if validate_receiver_url were ever bypassed upstream.
PROBE = f"""import re, sys, urllib.request, urllib.error
from urllib.parse import urlsplit
if (
    len(sys.argv) != 4
    or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{{0,127}}", sys.argv[2])
    or not re.fullmatch(r"[0-9]{{1,2}}", sys.argv[3])
    or not 0 < int(sys.argv[3]) <= 30
):
    sys.stderr.write('invalid-probe-input\\n')
    sys.exit(1)
_url = urlsplit(sys.argv[1])
if (
    any(ord(char) <= 32 or ord(char) >= 127 for char in sys.argv[1])
    or _url.scheme != 'http'
    or not _url.hostname
    or not re.fullmatch(r"{_HOSTNAME_PATTERN}", _url.hostname)
    or _url.username
    or _url.password
    or _url.path != '/probe'
    or _url.query
    or _url.fragment
    or not _url.port
):
    sys.stderr.write('invalid-probe-input\\n')
    sys.exit(1)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
request = urllib.request.Request(sys.argv[1], headers={{'X-Gate-Attempt': sys.argv[2]}})
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}), NoRedirect())
    with opener.open(request, timeout=float(sys.argv[3])) as response:
        response.read(1)
except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
    pass
print('agent-boundary-gate-probe-complete:' + sys.argv[2])
"""

# A fixed direct HTTP request: no proxy environment, redirects, shell interpolation,
# response buffering or target-supplied executable code. IO::Socket::IP is required.
PERL_PROBE = r"""use strict;
use warnings;
use IO::Socket::IP;
use Socket qw(SOCK_STREAM);
my ($host, $port, $attempt, $seconds) = @ARGV;
die "invalid-probe-input\n" unless @ARGV == 4
    && defined($host) && $host =~ /\A[a-zA-Z0-9:][a-zA-Z0-9.:-]{0,252}\z/
    && defined($port) && $port =~ /\A[0-9]{1,5}\z/ && $port > 0 && $port <= 65535
    && defined($attempt) && $attempt =~ /\A[a-zA-Z0-9][a-zA-Z0-9_.:\/-]{0,127}\z/
    && defined($seconds) && $seconds =~ /\A[0-9]{1,2}\z/ && $seconds > 0 && $seconds <= 30;
local $SIG{ALRM} = sub { die "request-timeout\n" };
local $SIG{PIPE} = 'IGNORE';
eval {
    alarm($seconds);
    my $socket = IO::Socket::IP->new(
        PeerHost => $host, PeerPort => $port, Type => SOCK_STREAM, Timeout => $seconds
    );
    if ($socket) {
        $socket->autoflush(1);
        my $authority = $host =~ /:/ ? "[$host]:$port" : "$host:$port";
        print $socket "GET /probe HTTP/1.1\r\nHost: $authority\r\n"
            . "X-Gate-Attempt: $attempt\r\nConnection: close\r\n\r\n";
        read($socket, my $byte, 1);
        close($socket);
    }
};
alarm(0);
print "agent-boundary-gate-probe-complete:$attempt\n";
"""


def validate_receiver_url(url: str) -> None:
    # Reject controls before urlsplit can normalize them away. The fixed probes
    # accept ASCII DNS names/IPv4/IPv6 literals, without scoped IPv6 zone identifiers.
    if any(ord(char) <= 32 or ord(char) >= 127 for char in url):
        raise ValueError("receiver URL contains unsupported characters")
    value = urlsplit(url)
    if (
        value.scheme != "http"
        or not value.hostname
        or not re.fullmatch(_HOSTNAME_PATTERN, value.hostname)
        or value.username
        or value.password
        or value.path != "/probe"
        or value.query
        or value.fragment
        or not value.port
    ):
        raise ValueError("receiver must be an explicit HTTP /probe endpoint")
