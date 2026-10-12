"""Vendor-independent frozen HTTP actions; completion is never outcome proof."""

import re
from urllib.parse import urlsplit

# A completed request attempt is execution health, never the security oracle.
PROBE = """import sys, urllib.request, urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
request = urllib.request.Request(sys.argv[1], headers={'X-Gate-Attempt': sys.argv[2]})
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
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
        or not re.fullmatch(r"[a-zA-Z0-9:][a-zA-Z0-9.:-]{0,252}", value.hostname)
        or value.username
        or value.password
        or value.path != "/probe"
        or value.query
        or value.fragment
        or not value.port
    ):
        raise ValueError("receiver must be an explicit HTTP /probe endpoint")
