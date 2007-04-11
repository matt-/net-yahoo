#!/usr/bin/perl

print "Content-type: text/html\n\n";

use strict;
use Term::ANSIColor;
require Win32::Console::ANSI if($^O eq "MSWin32");


print make_hex('When assigning to a list, if LIMIT is omitted, or zero, Perl supplies a LIMIT one larger than the number of vari- ables in the list, to avoid unnecessary work.  For the list above LIMIT would have been 4 by default.  In time critical applications it behooves you not to split into more fields than you really need.');


sub make_hex
{
    my ($data, $ret, $i) = (shift, '', 0);
	foreach my $d (grep $_, split(/(.{16})/, $data)) {
        my $out = sprintf "%.8X : ", $i+=16;
		$out .= sprintf("%-47s", join(' ',unpack( 'H2' x 16, $d)));
        $d =~ s/[\x00-\x1F\x95\xFF]/./g;
        $ret .= "\e[0;32m$out\e[0m   $d\n";
	}
    return $ret;
}