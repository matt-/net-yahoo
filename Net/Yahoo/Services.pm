package Net::Yahoo::Services;

use strict;
use warnings FATAL => 'all';

our $yahoo_serivces = {
    0x01 => {
         service => 'YAHOO_SERVICE_LOGON',
         action  => sub{}
    },
    0x02 => {
         service => 'YAHOO_SERVICE_LOGOFF',
         action  => sub{}
    },
    0x03 => {
         service => 'YAHOO_SERVICE_ISAWAY',
         action  => sub{}
    },
    0x04 => {
         service => 'YAHOO_SERVICE_ISBACK',
         action  => sub{}
    },
    0x05 => {
         service => 'YAHOO_SERVICE_IDLE',
         action  => sub{}
    },
    0x06 => {
         service => 'YAHOO_SERVICE_MESSAGE',
         action  => sub{}
    },
    0x07 => {
         service => 'YAHOO_SERVICE_IDACT',
         action  => sub{}
    },
    0x08 => {
         service => 'YAHOO_SERVICE_IDDEACT',
         action  => sub{}
    },
    0x09 => {
         service => 'YAHOO_SERVICE_MAILSTAT',
         action  => sub{}
    },
    0x0a => {
         service => 'YAHOO_SERVICE_USERSTAT',
         action  => sub{}
    },
    0x0b => {
         service => 'YAHOO_SERVICE_NEWMAIL',
         action  => sub{}
    },
    0x0c => {
         service => 'YAHOO_SERVICE_CHATINVITE',
         action  => sub{}
    },
    0x0d => {
         service => 'YAHOO_SERVICE_CALENDAR',
         action  => sub{}
    },
    0x0e => {
         service => 'YAHOO_SERVICE_NEWPERSONALMAIL',
         action  => sub{}
    },
    0x0f => {
         service => 'YAHOO_SERVICE_NEWCONTACT',
         action  => sub{}
    },
    0x10 => {
         service => 'YAHOO_SERVICE_ADDIDENT',
         action  => sub{}
    },
    0x11 => {
         service => 'YAHOO_SERVICE_ADDIGNORE',
         action  => sub{}
    },
    0x12 => {
         service => 'YAHOO_SERVICE_PING',
         action  => sub{}
    },
    0x13 => {
         service => 'YAHOO_SERVICE_GROUPRENAME',
         action  => sub{}
    },
    0x14 => {
         service => 'YAHOO_SERVICE_SYSMESSAGE',
         action  => sub{}
    },
    0x16 => {
         service => 'YAHOO_SERVICE_PASSTHROUGH2',
         action  => sub{}
    },
    0x18 => {
         service => 'YAHOO_SERVICE_CONFINVITE',
         action  => sub{}
    },
    0x19 => {
         service => 'YAHOO_SERVICE_CONFLOGON',
         action  => sub{}
    },
    0x1 => {
         service => 'YAHOO_SERVICE_CONFDECLINE',
         action  => sub{}
    },
    0x1b => {
         service => 'YAHOO_SERVICE_CONFLOGOFF',
         action  => sub{}
    },
    0x1c => {
         service => 'YAHOO_SERVICE_CONFADDINVITE',
         action  => sub{}
    },
    0x1d => {
         service => 'YAHOO_SERVICE_CONFMSG',
         action  => sub{}
    },
    0x1e => {
         service => 'YAHOO_SERVICE_CHATLOGON',
         action  => sub{}
    },
    0x1f => {
         service => 'YAHOO_SERVICE_CHATLOGOFF',
         action  => sub{}
    },
    0x20 => {
         service => 'YAHOO_SERVICE_CHATMSG',
         action  => sub{}
    },
    0x28 => {
         service => 'YAHOO_SERVICE_GAMELOGON',
         action  => sub{}
    },
    0x28 => {
         service => 'YAHOO_SERVICE_GAMELOGOFF',
         action  => sub{}
    },
    0x2a => {
         service => 'YAHOO_SERVICE_GAMEMSG',
         action  => sub{}
    },
    0x46 => {
         service => 'YAHOO_SERVICE_FILETRANSFER',
         action  => sub{}
    },
    0x4a => {
         service => 'YAHOO_SERVICE_VOICECHAT',
         action  => sub{}
    },
    0x4c => {
         service => 'YAHOO_AUTH_INIT',
         action  => sub{
			my $self = shift;
            my $packet = shift;
	        $self->send_packet({
	                'Status' => 0,
	                'SessionID' => $self->{SessionId},
	                'Version' => 12,
	                'ServiceCode' => 87,
	                'data' => {1 => $self->{Handle}}
	            });
         }
    },
    0x4b => {
         service => 'YAHOO_SERVICE_NOTIFY',
         action  => sub{}
    },
    0x4d => {
         service => 'YAHOO_SERVICE_P2PFILEXFER',
         action  => sub{}
    },
    0x4f => {
         service => 'YAHOO_SERVICE_PEERTOPEER',
         action  => sub{}
    },
    0x54 => {
         service => 'YAHOO_SERVICE_AUTHRESP',
         action  => sub{

         }
    },
    0x55 => {
         service => 'YAHOO_SERVICE_LIST',
         action  => sub{}
    },
    0x57 => {
         service => 'YAHOO_SERVICE_AUTH',
         action  => sub{
			my $self = shift;
            my $packet = shift;
           my ($enc1, $enc2) = $self->{Auth}->y_auth($self->{Handle},$self->{Password},$packet->{data}->{94});
            $self->send_packet({
                    'Status' => 0,
                    'SessionID' => $self->{SessionId},
                    'Version' => 12,
                    'ServiceCode' => 84,
                    'data' => {
                        6 => $enc1,
                        96 => $enc2,
                        0 => $self->{Handle},
                        2 => $self->{Handle},
                        192 => 435028005,
                        2 => 1,
                        1 => $self->{Handle},
                        135 => '6,0,0,1750',
                        148 => 300,
                    }
                });
         }
    },
    0x83 => {
         service => 'YAHOO_SERVICE_ADDBUDDY',
         action  => sub{}
    },
    0x84 => {
         service => 'YAHOO_SERVICE_REMBUDDY',
         action  => sub{}
    },
    0x85 => {
         service => 'YAHOO_SERVICE_IGNORECONTACT',
         action  => sub{}
    },
    0x86 => {
         service => 'YAHOO_SERVICE_REJECTCONTACT',
         action  => sub{}
    },
    0xbe => {
         service => 'YAHOO_SERVICE_PICTURE',
         action  => sub{}
    },
};