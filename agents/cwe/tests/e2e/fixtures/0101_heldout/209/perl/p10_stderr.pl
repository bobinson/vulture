# Feature 0101 held-out (LLD 4.6), CWE-209 in Perl, a language no 0101 probe or
# lexicon touched. Disclosure is the error's message, string form or raw value reaching
# the peer; a fixed text, a code or a log line is not. Every identifier is invented.
# HELD-OUT-TOKENS: responder, eval, Tiny, encode_json
use strict;
use warnings;
use Try::Tiny;

sub report_app {
    my ($env) = @_;
    return sub {
        my ($responder) = @_;
        my $writer = $responder->([500, ['Content-Type' => 'text/plain']]);
        my $ok = eval { render_report($env); 1 };
        return if $ok;
        my $err = $@;
        # EXPECT-NEXT: clean
        print {*STDERR} $err;
        $writer->close;
    };
}
1;
