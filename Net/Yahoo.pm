#================================================
package Net::Yahoo;
#================================================

=head1 Yahoo v1.0

=cut

use strict;
use warnings;
use LWP::UserAgent;
use Data::Dumper;

# IO
use IO::Select;
use IO::Socket::INET;

# coloring for console
use Term::ANSIColor;
$Term::ANSIColor::AUTORESET = 1;
require Win32::Console::ANSI if($^O eq "MSWin32");

use Net::Yahoo::Util;


# this is the seporator used in yahoo packets
my $sep = "\xC0\x80";


#checksum
sub checksum {
	    my $o = tell(DATA);
	    seek DATA,0,0;
	    local $/;
	    my $t = unpack("%32C*",<DATA>) % 65535;
	    seek DATA,$o,0;
        my $str = do{local $/; <DATA>};
        return $t;
};

=head2 Methods

=item
new

Creates an instance of the Yahoo object used to communicate with Yahoo Servers.

=cut

sub new
{
	my $class = shift;

	my $self  =
	{
	    Host          => 'cs1.msg.dcn.yahoo.com',
	    Port          => 5050,
	    Handle        => '',
	    Password      => '',
	    Debug         => 0,
	    ShowTX        => 0,
	    ShowRX        => 0,
	    AutoReconnect => 1,
	    Select        => new IO::Select(),
	    Notification  => undef,
	    Connections   => {},
	    Connected     => 0,
	    @_
	};
	bless( $self, $class );
    return $self;
}

sub DESTROY
{
	my $self = shift;
	# placeholder for possible destructor code
}

sub AUTOLOAD
{
	my $self = shift;
	$self->error( "method $YAHOO::AUTOLOAD not defined" ) if( $self->{AutoloadError} );
}

# add debug levels and ansi coloring to this and
# tx/rx messages
# * Dedug types, [message (blue). notice (yellow) warning (red)

sub debug
{
	my $self = shift;
	my $message = shift || '';

	if( defined $self->{handler}->{Debug} )
	{
		$self->call_event( $self, 'Debug', $message );
	}
	elsif( $self->{Debug} )
	{
		print( "$message\n" );
	}
	return 1;
}




=item
connect

Connect to Yahoo. Call this after your object is created and your event handlers are set.

=cut

sub connect
{
    my $self = shift;
    # if success set a varrible fo uptime stats
    $self->{Connected} = time;

    $self->{socket} = new IO::Socket::INET->new(
    						PeerAddr => $self->{Host},
                            PeerPort => $self->{Port},
                            Proto => 'tcp') or die "Couldn't connect!";

    $self->{Select}->add($self->{socket});

	$self->send_packet({
    		'Status' => 0,
	        'SessionID' => 48,
	        'Version' => 12,
	        'ServiceCode' => 76,
	        'data' => ''
	    });

    #$self->call_event( $self, 'connected', $self->{Connected});
}

=item
disconnect

Disconnect from Yahoo.

=cut

sub disconnect
{
        my $self = shift;
        foreach my $convo (values %{$self->getConvoList()})
        {
                $convo->leave();
        }
        $self->{Notification}->disconnect();
        $self->{Connected} = 0;
        return 1;
}

=item
isConnected()

Checks if the connection is active.

=cut

sub isConnected
{
        my $self = shift;
        return $self->{Connected};
}

=item
uptime()

Get the current uptime in seconds (since the last connection).

=cut

sub uptime
{
        my $self = shift;
        return ($self->{Connected}) ? (time - $self->{Connected}) : 0;
}

=item
do_one_loop()

Process a single cycle's worth of incoming and outgoing messages.  This should be done at a regular intervals, preferably under a second.

=cut

sub do_one_loop
{
	my $self = shift;
	my $pack;
    my $data;
    my $in;
    # return immediately if we are not connected
	return if( !$self->{Connected} );

    select ( undef, undef, undef ,.1); #sleep for .1 second

    my @ready = $self->{Select}->can_read(.1);
    foreach my $fh (@ready){
        sysread( $fh, $pack, 2048, length( $pack || '' ) );
        my @packs = split("YMSG", $pack);
	    shift @packs;
	    foreach my $i (@packs) {
	        (   $in->{Version},
	            $in->{Length},
	            $in->{ServiceCode},
	            $in->{Status},
	            $in->{SessionID},$data
	        ) = unpack("nNnN2a*",$i);
	        my %dat = split("\xC0\x80", $data);
	        $in->{data} = \%dat;
            $pack = Net::Yahoo::Util::make_hex($pack);
            print colored(Dumper($in), 'red'), "\n" if($self->{TXRXDump});
            print colored($pack, 'red'), "\n" if($self->{ShowRX});
	    }
        $pack = "";
    }

}


=item
setHandler($event, $handler)

$event should be an event listed in the events section.  These are called based on information sent by MSN,
receiving a message is an event, status changes are events, getting a call is an event, etc.

                 $yahoo->setHandler( Connected => \&connected );

                 sub connected {
                                 my $self = shift;
                                 print "Yay we connected";
                 }

=cut

sub setHandler
{
        my $self = shift;
        my ($event, $handler) = @_;
        $self->{handler}->{$event} = $handler;
}

=item
	setHandlers( $event1 => $handler1, $event2 => $handler2)

	Expects a list of events and handlers.

	my $yahoo = new Yahoo;
	$yahoo->setHandlers(
    	Connected    => \&connected,
		Disconnected => \&disconnected
    );

=cut

sub setHandlers
{
	my $self = shift;
	my $handlers = { @_ };
	for my $event (keys %$handlers)
	{
		$self->setHandler( $event, $handlers->{$event} );
	}
}

sub call_event
{
	my $self = shift;
	my $receiver = shift;
	my $event = shift;
	# get and run the handler if it is defined
	my $function = $self->{handler}->{$event};
	return &$function( $receiver, @_ ) if( defined $function );
	# get and run the default handler if it is defined
	$function = $self->{handler}->{Default};
	return &$function( $receiver, $event, @_ ) if( defined $function );
	return undef;
}

sub send_packet{
	my $self = shift;
    my $packet = shift;
    print colored(Dumper($packet), 'green'), "\n" if($self->{TXRXDump});

    my $pack = pack("a4nNnN2",
    		"YMSG",
            $packet->{Version},
            length($packet->{data}),
            $packet->{ServiceCode},
            $packet->{Status},
            $packet->{SessionID}).$packet->{data};
    $self->{socket}->print($pack);
    $pack = Net::Yahoo::Util::make_hex($pack);
    print colored("$pack", 'green'), "\n" if($self->{ShowTX});
}

1;
__DATA__
