# ----------------------------------------------------------------------------
# Distributed under the "do-what-you-want-but-don't-blame-me" license
# <matt@www.com> wrote this file.  As long as you retain this notice you
# can do whatever you want with it. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matt Austin
# ----------------------------------------------------------------------------

# All code based off the GAIM source some java client and bits of a
# python client.  See also the data.pl.

package Yahoo::Auth;

use strict;
use vars qw($VERSION);
use warnings FATAL => 'all';

#Math::BigInt::GMP (install this module will make it faster)
use bigint lib => "GMP";

use Crypt::PasswdMD5 qw(unix_md5_crypt);
use Digest::MD5 qw(md5);
use MIME::Base64;

# My sha module for the sizelo problem,
# the Digest::SHA because its faster
use Digest::SHA1;
use SHA;

# Include the tables & build them
do("data.pl");

# Set version of module
$VERSION = '0.01';

sub new {
        my $class = shift;
        my $self  = bless({
                Debug    => 0,
                Power    => 4294967296,
                Alpha    => "qzec2tb3um1olpar8whx4dfgijknsvy5",
                Op       => "+|&%/*^-",
                CryptKey => '$1$_2S43d5f$',
                @_
        }, ref($class) || $class);

        $self->buildTables();
        return $self;
}

sub y_auth {
        my $self     = shift;
        my $username = shift;
        my $password = shift;
        my $seed     = shift;

        # Phase 1
        my (@magic, $operand);
        for my $char (grep { !/[\(\)]/ } split(//, $seed)) {
                # Check if this is a normal character
                if($char =~ /\w/) {
                        # Define the operand
                        $operand = index($self->{Alpha}, $char) << 3;
                } else {
                        # Push it into the magic bag of numbers
                        push(@magic, ($operand | index($self->{Op}, $char)) & 255);
                }
        }

        # Phase 2
        for(my $i = $#magic - 1; $i >= 0; $i--) {
                $magic[$i+1] = (($magic[$i] * 205) ^ $magic[$i+1]) & 255;
        }

        # Phase 3
        my ($ix, $cvalue) = (1, "");
        for(my $l = 0; $l < 20; $l += 2) {
                # Set two variables
                my $cl = my $bl = $magic[$ix++];

                # Check if we can continue or not
                last if($ix >= $#magic);

                # Check for the value of $cl
                if($cl > 0x7f) {
                        # Check again for the value of cl 8-)
                        $bl  = ($cl < 0xe0 ? ($cl & 0x1f) << 6 : (($magic[$ix++] & 0x3f) + (($cl & 0x0f) << 6)) << 6);
                        $cl  = $magic[$ix++];
                           $bl += ($cl & 0x3f);
                }

                # Compute value
                $cvalue .= chr(($bl & 0xff00) >> 8) . chr($bl & 0xff);
        }


        # Set a couple of thingies and continue with the loops
        my $cval4 = substr($cvalue, 0, 4);
        my $cvale = substr($cvalue, 4, 17);
        my ($depth, $table) = (0, 0);
        OUTER: for(my $i = 0; $i < 65535; $i++) {
                # Calculate $ix and $iy only once every 5 $j loops (saves time!)
                my ($ix, $iy) = (chr($i % 256), chr(($i >> 8) % 256));
                INNER: for(my $j = 0; $j < 5; $j++) {
                        # Fetch the chl value and hash it (j won't surpass 5, so why modulo?!)
                        my $chl = $cval4 . $ix . $iy . chr($j);
                        my $md5 = md5($chl);

                        # Check if we have a match..
                        if($cvale eq substr($md5, 0, 17)) {
                                # We found the depth & table, quit!
                                ($depth, $table) = ($i, $j);
                                last OUTER; # Jump out of the $i loop
                        }
                }
        }

        # Fetch the X values from the tables
        print "> table lookup 1\n" if($self->{Debug});
        my $xu = $self->get_x(unpack("V", $cval4), $table, $depth);

        print "> table lookup 2\n" if($self->{Debug});
        $xu = $self->get_x($xu, $table, $depth);

        my $value = pack('V', $xu);
        print "* done table lookup\n" if($self->{Debug});

        # Get the Base64 encoded MD5 digest
        my $password_hash = $self->b64(md5($password));
        chop($password_hash);

        # Then do the same with the combination of $password/$cryptkey
        my $crypt_hash = $self->b64(md5(unix_md5_crypt($password, $self->{CryptKey})));
        chop($crypt_hash);

        # For each of the input strings do the thingamabob
        my $alphabet = [ [split(//, "FBZDWAGHrJTLMNOPpRSKUVEXYChImkwQ")], [split(//, "F0E1D2C3B4A59687"), ("a".."p")] ];
        my $delims         = [',',';'];
        my $output         = [];
        for my $input ($password_hash, $crypt_hash) {
                # Calculate a set of XOR hashed passwords
                my $hash_xor = $self->get_xor($input);

                # Calculate some more crap (two rounds of SHA1)
                print "> sh1 1 of 2\n" if($self->{Debug});
                my $s1 = SHA->new($hash_xor->[0]);
                   $s1->{sizelo} = 0x01ff;
                   $s1->update($value);

                print "> sh1 2 of 2\n" if($self->{Debug});
                my $digests = [$s1->digest(), ""];

                # Use Digest:;SHA for this part because its faster!
                # my $s2 = SHA->new($hash_xor->[1]);
                # $s2->update($digests->[0]);
                # $digests->[1] = $s2->digest();

                my $s2 = Digest::SHA1->new();
                   $s2->add($hash_xor->[1]);
                   $s2->add($digests->[0]);
                   $digests->[1] = $s2->digest();

                # Resp 6 part of the auth mechanism
                print "* sh1 done\n" if($self->{Debug});
                my $digest2 = [ split(//, $digests->[1]) ];
                my $outstr  = "";

                # Loop over the information, yatta yatta
                for(my $k = 0; $k < 20; $k += 2) {
                        # Fetch $v value
                        my $v  = ord($digest2->[$k]) << 8;
                           $v += ord($digest2->[$k+1]);

                        # Look-up variables
                        $outstr .= $self->get_lookup($v, 0x0b, $alphabet->[0], "=");
                        $outstr .= $self->get_lookup($v, 0x06, $alphabet->[1],  "");
                        $outstr .= $self->get_lookup($v, 0x01, $alphabet->[1],  "");

                        # Final look up with delimiters
                        $outstr .= $delims->[$v & 0x01];
                }

                # Push the output into the $output variable
                push(@{$output}, $outstr);
        }

        # Then return the string
        return @{$output};
}

sub get_x {
        my ($self, $xu, $table, $depth) = @_;

        # Don't do any calculations if $table is 0
        return $xu if($table == 0);

        # Fetch the $fn and then get it by some calculations
        my $fn = $self->{x_fn}[$table - 1][$xu % 96];
        return $self->get_fn($fn, $xu, $table, $depth);
}

sub get_fn {
        my ($self, $fn, $xu, $table, $depth) = @_;

        # Set $a, $b, $c & $d
        my ($a, $b, $c, $d) = map { ($xu >> $_) & 0xff } (0, 8, 16, 24);
        my ($z, $p1, $p2)   = (0, 0, 0);

        # Fetch the type of FN and calculate
        my $fntype =  $self->{fntype}->{$fn};

        if($fntype == 0) {
                # Fetch $unk field
                my $unk = $self->{unk_bitfield}->{$self->{fn_unk_bitfield}->{$fn}};
                for(my $i = 0; $i < 32; $i++) {
                        # Perform calculations on $z
                        $z  = (((($xu >> $i) & 0x01) << $unk->[$i]) | (~(0x01 << $unk->[$i]) & $z));
                        $z %= $self->{Power} if($z > $self->{Power}); # Only perform if z>power, otherwise (z%=power)==z
                }

                # Make a copy of $z?!
                $xu = $z;

        } elsif($fntype == 1) {
                # Fetch the $unk field again
                my $unk = $self->{unk_lookup}->{$self->{fn_unk_lookup}->{$fn}};

                # Set $p1 and $p2
                $p1 = (($unk->[$d] << 8) | $unk->[$c]);
                $p2 = (($p1 << 8) | $unk->[$b]);

                # Then set $xu and module (only if necessary -- see above)
                $xu  = (($p2 << 8) | $unk->[$a]);
                $xu %= $self->{Power} if($xu > $self->{Power});

        } elsif($fntype == 2) {
                # Code is getting shorter and shorter eh?!
                my ($mul, $add) = @{$self->{unk_muladd}->{$fn}};
                $xu *= $mul; # Do this in two seperate steps, it's faster
                $xu += $add; # Ditto
                $xu %= $self->{Power} if($xu > $self->{Power});

        } elsif($fntype == 3) {
                # This must be the shortest of them all :P
                my $ex_or = $self->{unk_xor}->{$fn};

                # Perform operations on $xu (^= does not have to make a copy of $xu)
                $xu ^= $ex_or;
                $xu %= $self->{Power} if($xu > $self->{Power});
        }

        # Check if we can return $xu alright
        return $xu if($fn == 0 || $depth < 2);

        # Perform more calculations on $a, $b, $c & $d
        ($a, $b, $c, $d) = map { ($xu >> $_) & 0xff } (0, 8, 16, 24);

        # Then some crap on $p1, $p2 & $z
        $z  = (((((($a * 0x9e3779b1) ^ $b) * 0x9e3779b1) ^ $c) * 0x9e3779b1) ^ $d) * 0x9e3779b1;
        $z %= $self->{Power} if($z > $self->{Power});

        # Then calculate some stuff and finally return the table look up information
        my $n  = (((($z ^ ($z >> 8)) >>16) ^ $z) ^ ($z >> 8)) & 0xff;
           $n %= $self->{Power} if($n > $self->{Power});

        # Alllmost there!
        return $self->get_fn($self->{x_fn}[$table - 1]->[$n % 96], $xu * 0x10dcd, $table, --$depth);
}

sub get_xor {
        my ($self, $string) = @_;

        # Calculate the silly thingomajigo
        my $hash_xor = ["", ""];
        for my $char (split(//, $string)) {
                # Fetch the ASCII value of $char
                $char = ord($char);

                # Then stuff the XOR character in the array
                $hash_xor->[0] .= chr($char ^ 0x36);
                $hash_xor->[1] .= chr($char ^ 0x5c);
        }

        # Check if the XOR strings are smaller than 64
        if((my $rem = 64 - length($hash_xor->[1])) > 0) {
                # Append the normal characters till it is 64 characters in length
                $hash_xor->[0] .= chr(0x36) x $rem;
                $hash_xor->[1] .= chr(0x5c) x $rem;
        }

        # Then return it aight
        return $hash_xor;
}

sub get_lookup {
        # Look up information
        my ($self, $v, $hx, $alphabet, $append) = @_;
        my $value = ($v >> $hx) & 0x1f;
        return $alphabet->[$value] . $append;
}


sub b64 {
        # Encode, replace, return
        my ($self, $data) = @_;
        my $enc  = encode_base64($data);
           $enc =~ s/\=/\-/g;
           $enc =~ s/\+/\./g;
           $enc =~ s/\//\_/g;

        return $enc;
}


1;
