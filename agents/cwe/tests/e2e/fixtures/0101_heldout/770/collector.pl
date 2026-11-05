# Feature 0101 held-out (LLD 4.6), CWE-770 in Perl, a language no 0101 probe or
# lexicon touched. An array or string that grows once per line or chunk read from a
# peer, with no cap, is unbounded; growth over a finite in-memory list, or growth
# checked against a maximum, is not. Every identifier is invented.
# HELD-OUT-TOKENS: sysread, chomp
use strict;
use warnings;

my $max_lines = 5000;

sub slurp_lines {
    my ($sock) = @_;
    my @lines;
    while (my $line = <$sock>) {
        chomp $line;
        # EXPECT-NEXT: clean held-out-miss (concept: finding)
        push @lines, $line;
    }
    return \@lines;
}

sub slurp_bytes {
    my ($sock) = @_;
    my $buffer = '';
    while (sysread($sock, my $chunk, 4096)) {
        # EXPECT-NEXT: clean held-out-miss (concept: finding)
        $buffer .= $chunk;
    }
    return $buffer;
}

sub slurp_lines_oo {
    my ($handle, $sink) = @_;
    while (defined(my $line = <$handle>)) {
        # EXPECT-NEXT: clean held-out-miss (concept: finding)
        $sink->add($line);
    }
}

sub slurp_lines_capped {
    my ($sock) = @_;
    my @lines;
    while (my $line = <$sock>) {
        # EXPECT-NEXT: clean
        push @lines, $line;
        last if @lines >= $max_lines;
    }
    return \@lines;
}

sub doubled {
    my (@items) = @_;
    my @out;
    for my $item (@items) {
        # EXPECT-NEXT: clean
        push @out, $item * 2;
    }
    return @out;
}

sub fields_of {
    my ($body) = @_;
    my @parts;
    for my $part (split /,/, $body) {
        # EXPECT-NEXT: clean
        push @parts, $part;
    }
    return @parts;
}

sub numbered {
    my ($sink) = @_;
    for my $n (1 .. 10) {
        # EXPECT-NEXT: clean
        $sink->add($n);
    }
}
1;
