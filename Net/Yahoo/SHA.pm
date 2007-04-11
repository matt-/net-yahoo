package SHA;


# ----------------------------------------------------------------------------
# Distributed under the "do-what-you-want-but-don't-blame-me" license
# <matt@www.com> wrote this file.  As long as you retain this notice you
# can do whatever you want with it. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matt Austin
# ----------------------------------------------------------------------------


# The Digest::SHA1 module wouldnt let me change the value of the hash
# before the digest


#use bigint lib => "GMP";
use Math::BigInt lib => 'GMP';
use strict;
use warnings FATAL => 'all';

use constant INTMAX => 2147483647;
use constant INTMIN => -2147483648;

sub new
{
        my $class = shift;
        my $s = shift;
        my $self = {};
        bless $self, $class;
        $self->init();
        $self->update($s) if $s;
        return $self;
}

sub init
{
        my $self = shift;
        $self -> {lenw} = 0;
        $self -> {sizehi} = 0;
        $self -> {sizelo} = 0;
        $self -> {h} = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        $self -> {w} = [0 .. 79];
        foreach my $i (0 .. 79)
        {
                $self -> {w}[$i] = 0;
                $self -> {mask} = [0..32];
                $self -> {mask}[0] = 0x00000000;
                $self -> {mask}[1] = 0x80000000;
                $self -> {mask}[2] = 0xc0000000;
                $self -> {mask}[3] = 0xe0000000;
                $self -> {mask}[4] = 0xf0000000;
                $self -> {mask}[5] = 0xf8000000;
                $self -> {mask}[6] = 0xfc000000;
                $self -> {mask}[7] = 0xfe000000;
                $self -> {mask}[8] = 0xff000000;
                $self -> {mask}[9] = 0xff800000;
                $self -> {mask}[10] = 0xffc00000;
                $self -> {mask}[11] = 0xffe00000;
                $self -> {mask}[12] = 0xfff00000;
                $self -> {mask}[13] = 0xfff80000;
                $self -> {mask}[14] = 0xfffc0000;
                $self -> {mask}[15] = 0xfffe0000;
                $self -> {mask}[16] = 0xffff0000;
                $self -> {mask}[17] = 0xffff8000;
                $self -> {mask}[18] = 0xffffc000;
                $self -> {mask}[19] = 0xffffe000;
                $self -> {mask}[20] = 0xfffff000;
                $self -> {mask}[21] = 0xfffff800;
                $self -> {mask}[22] = 0xfffffc00;
                $self -> {mask}[23] = 0xfffffe00;
                $self -> {mask}[24] = 0xffffff00;
                $self -> {mask}[25] = 0xffffff80;
                $self -> {mask}[26] = 0xffffffc0;
                $self -> {mask}[27] = 0xffffffe0;
                $self -> {mask}[28] = 0xfffffff0;
                $self -> {mask}[29] = 0xfffffff8;
                $self -> {mask}[30] = 0xfffffffc;
                $self -> {mask}[31] = 0xfffffffe;
                $self -> {mask}[32] = 0xffffffff;
        }
}

sub digest
{
        my $self = shift;
        my $pad0x80 = chr(0x80);
        my $pad0x00 = chr(0x00);

        my @padlen;
        $padlen[0] = $self -> _shr($self -> {sizehi}, 24) & 255;
        $padlen[1] = $self -> _shr($self -> {sizehi}, 16) & 255;
        $padlen[2] = $self -> _shr($self -> {sizehi}, 8) & 255;
        $padlen[3] = $self -> _shr($self -> {sizehi}, 0) & 255;
        $padlen[4] = $self -> _shr($self -> {sizelo}, 24) & 255;
        $padlen[5] = $self -> _shr($self -> {sizelo}, 16) & 255;
        $padlen[6] = $self -> _shr($self -> {sizelo}, 8) & 255;
        $padlen[7] = $self -> _shr($self -> {sizelo}, 0) & 255;

        $self -> update($pad0x80);
        while ($self -> {lenw} != 56)
        {
                $self -> update($pad0x00);
        }
        $self -> update($self -> _tostring(@padlen));


        my @hashout;
        foreach my $i (0 .. 19)
        {
                $hashout[$i] = int(($self -> {h}[$i / 4] >> 24) % 256);
                $self -> {h}[$i / 4] <<= 8;
                $self -> {h}[$i / 4] &= 0xffffffff;
                $self -> {h}[$i / 4] = $self -> _overflow($self -> {h}[$i / 4]);
        }
        my $output = $self -> _tostring(@hashout);
        $self -> init();
        return $output;
}

sub _hashblock
{
                my $self = shift;
                foreach $_ (16 .. 80)
                {
                        $self -> {w}[$_] = $self -> _overflow($self -> _rotl($self -> {w}[$_ - 3] ^ $self -> {w}[$_ - 8] ^ $self -> {w}[$_ - 14] ^ $self -> {w}[$_ - 16], 1));
                }
                my $a = Math::BigInt->new($self -> _overflow($self -> {h}[0]));
                my $b = Math::BigInt->new($self -> _overflow($self -> {h}[1]));
                my $c = Math::BigInt->new($self -> _overflow($self -> {h}[2]));
                my $d = Math::BigInt->new($self -> _overflow($self -> {h}[3]));
                my $e = Math::BigInt->new($self -> _overflow($self -> {h}[4]));


                 my $temp;
                foreach $_ (0 .. 19)
                {
                        $temp = ($self -> _rotl($a, 5) + ((($c ^ $d) & $b) ^ $d) + $e + $self -> {w}[$_] + 0x5a827999) & 0xffffffff;
                        $e = $d;
                        $d = $c;
                        $c = $self -> _overflow($self -> _rotl($b, 30));
                        $b = $a;
                        $a = $self -> _overflow($temp);
                }

                foreach $_ (20 .. 39)
                {
                        $temp = ($self -> _overflow($self -> _rotl($a, 5)) + ($b ^ $c ^ $d) + $e + $self -> {w}[$_] + 0x6ed9eba1) & 0xffffffff;
                        $e = $d;
                        $d = $c;
                        $c = $self -> _overflow($self -> _rotl($b, 30));
                        $b = $a;
                        $a = $self -> _overflow($temp);
                }

                foreach $_ (40 .. 59)
                {
                        $temp = ($self -> _rotl($a, 5) + (($b & $c) | ($d & ($b | $c))) + $e + $self -> {w}[$_] + 0x8f1bbcdc) & 0xffffffff;
                        $e = $d;
                        $d = $c;
                        $c = $self -> _overflow($self -> _rotl($b, 30));
                        $b = $a;
                        $a = $self -> _overflow($temp);
                }

                foreach $_ (60 .. 79)
                {
                        $temp = ($self -> _rotl($a, 5) + ($b ^ $c ^ $d) + $e + $self -> {w}[$_] + 0xca62c1d6) & 0xffffffff;
                        $e = $d;
                        $d = $c;
                        $c = $self -> _overflow($self -> _rotl($b, 30));
                        $b = $a;
                        $a = $self -> _overflow($temp);
                }

                $self -> {h}[0] = $self -> _overflow($self -> {h}[0]);
                $self -> {h}[1] = $self -> _overflow($self -> {h}[1]);
                $self -> {h}[2] = $self -> _overflow($self -> {h}[2]);
                $self -> {h}[3] = $self -> _overflow($self -> {h}[3]);
                $self -> {h}[4] = $self -> _overflow($self -> {h}[4]);

                $self -> {h}[0] += $a;
                $self -> {h}[1] += $b;
                $self -> {h}[2] += $c;
                $self -> {h}[3] += $d;
                $self -> {h}[4] += $e;

                $self -> {h}[0] = $self -> _overflow($self -> {h}[0]);
                $self -> {h}[1] = $self -> _overflow($self -> {h}[1]);
                $self -> {h}[2] = $self -> _overflow($self -> {h}[2]);
                $self -> {h}[3] = $self -> _overflow($self -> {h}[3]);
                $self -> {h}[4] = $self -> _overflow($self -> {h}[4]);
}

sub _overflow
{
        my $self = shift;
        my $n = shift;
        if($n > INTMAX)
        {
                return INTMIN + ($n % INTMAX) - 1;
        }
        elsif($n < INTMIN)
        {
                return INTMAX + ($n % INTMIN) + 1;
        }
        return $n;

}

sub _rotl
{
        my $self = shift;
        my ($x,$n) = @_;
        return (($x << $n) | ($self -> _shr($x, (32 - $n)))) & 0xffffffff;
}
sub _shr
{
        my ($self, $x, $n) = @_;
        return ($x >> $n) & ~ ($self -> {mask}[$n]);
}

sub _tostring
{
        my ($self, @l) = @_;
        my $s;
        foreach my $item (@l)
        {
                 $s .= chr($item % 256);
        }
        return $s;
}

sub update
{
        my ($self, $s) = @_;
        my @chars = split //,$s;
        foreach my $i (@chars)
        {
                $self -> {w}[$self -> {lenw} / 4] <<= 8;
                $self -> {w}[$self -> {lenw} / 4] |= ord($i);
                $self -> {lenw} += 1;
                if( $self -> {lenw} % 64 == 0 )
                {
                        $self -> _hashblock();
                        $self -> {lenw} = 0;
                }
                $self -> {sizelo} += 8;
                $self -> {sizehi} += $self -> {sizelo} < 8
        }
}


1;