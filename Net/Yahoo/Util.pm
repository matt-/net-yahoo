#!/usr/bin/perl

#================================================
package Net::Yahoo::Util;
#================================================

use strict;

sub make_hex
{
    my ($data, $ret, $i) = (shift, '', 0);
	foreach my $d (grep $_, split(/(.{16})/, $data)) {
        my $out = sprintf "%.8X : ", $i+=16;
		$out .= sprintf("%-47s", join(' ',unpack( 'H2' x 16, $d)));
        $d =~ s/[\x00-\x1F\x95\xFF]/./g;
        $ret .= "$out   $d\n";
	}
    return $ret;
}

1;