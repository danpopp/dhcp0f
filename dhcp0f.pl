#!/usr/bin/perl 

=head1 NAME

dhcp0f.pl - Passive DHCP analyzer with OS fingerprinting on the LAN through DHCP

=head1 SYNOPSIS

dhcp0f.pl [options]

 Options:
   -k      Fingerbank API key
   -i      Interface (default: "eth0")
   -f      Filter (eg. "host 128.103.1.1")
   -c      CHADDR (show requests from specific client)
   -d      Database path (/path/to/fingerbank/sqlite.db) [experimental]
   -t      DHCP message type
             Value   Message Type
             -----   ------------
               1     DHCPDISCOVER
               2     DHCPOFFER
               3     DHCPREQUEST
               4     DHCPDECLINE
               5     DHCPACK
               6     DHCPNAK
               7     DHCPRELEASE
               8     DHCPINFORM
   -v      verbose 
   -h      Help

=cut
require 5.8.0;

use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin . '/lib';
use lib $FindBin::Bin . '/extlib';

use Config::IniFiles;
use Data::Dumper;
use File::Basename qw(basename);
use Getopt::Std;
use Log::Log4perl qw(:easy :no_extra_logdie_message);
use Net::Pcap 0.16;
use Pod::Usage;
use POSIX;
use Try::Tiny;
use DBI;
use Data::Dumper;
use DBD::SQLite;
use Util qw(clean_mac);
use pf::util::dhcp;
use fingerbank::api;

my %args;
getopts( 'k:t:i:f:d:c:o:huv', \%args );

my $verbose = $INFO;
if ( $args{v} ) {
    $verbose = $DEBUG;
}

Log::Log4perl->easy_init({ level  => $verbose, layout => '%m%n' });
my $logger = Log::Log4perl->get_logger('');                                                                             

my $dbpath = $args{d} || "/opt/pwnix/dhcp0f/fingerbank/fingerbank.db";

if ($args{'d'}) {
	unless ( -r $dbpath ) {
		$logger->info("SQLite DB does not exist or is not readable! ");
	}
}

unless($args{'k'}){
    $logger->info("No API key specified!");
}

{
 no warnings;
 if ($args{d} & $args{'k'}){
    $logger->fatal("Please choose either API or Local SQLite ( -k OR -d), not BOTH.");
    pod2usage( -verbose => 1 );
 }
}

my $interface = $args{i} || "eth0";

if ( $args{h} || !$interface ) {
    pod2usage( -verbose => 1 );
}

my $chaddr_filter;
if ( $args{c} ) {
    $chaddr_filter = clean_mac( $args{c} );
}
my $filter = "(udp and (port 67 or port 68))";
if ( $args{f} ) {
    $filter .= " and " . $args{f};
}
my $type;
if ( $args{t} ) {
    $type = $args{t};
}
my $unknown;
if ( $args{u} ) {
    $unknown = 1;
}
my %msg_types;
$msg_types{'1'}   = "subnet mask";
$msg_types{'3'}   = "router";
$msg_types{'4'}   = "time server";
$msg_types{'6'}   = "dns servers";
$msg_types{'12'}  = "hostname";
$msg_types{'15'}  = "domain";
$msg_types{'23'}  = "default ttl";
$msg_types{'28'}  = "broadcast";
$msg_types{'31'}  = "router discovery";
$msg_types{'43'}  = "vendor specific information (43)";
$msg_types{'44'}  = "netbios nameserver";
$msg_types{'46'}  = "netbios node type";
$msg_types{'50'}  = "requested ip address";
$msg_types{'51'}  = "address time";
$msg_types{'53'}  = "message type";
$msg_types{'54'}  = "dhcp server id";
$msg_types{'55'}  = "requested parameter list";
$msg_types{'57'}  = "dhcp max message size";
$msg_types{'58'}  = "renewal time";
$msg_types{'59'}  = "rebinding time";
$msg_types{'60'}  = "vendor id";
$msg_types{'61'}  = "client id";
$msg_types{'66'}  = "servername";
$msg_types{'67'}  = "bootfile";
$msg_types{'81'}  = "fqdn";
$msg_types{'82'}  = "agent information (82)";
$msg_types{'150'} = "cisco tftp server (150)";
$msg_types{'116'} = "dhcp auto-config";

my $filter_t;
my $net;
my $mask;
my $opt = 1;
my $err;

my $pcap_t = Net::Pcap::pcap_open_live($interface, 576, 1, 0, \$err)
    or $logger->logdie("Unable to open network capture: $err");

if ( ( Net::Pcap::compile( $pcap_t, \$filter_t, $filter, $opt, 0 ) ) == -1 ) {
    $logger->logdie("Unable to compile filter string '$filter'");
}

Net::Pcap::setfilter( $pcap_t, $filter_t );

$logger->info("Starting to listen on $interface with filter: $filter");
Net::Pcap::loop( $pcap_t, -1, \&process_pkt, $interface );

sub process_pkt {
    my ( $user_data, $hdr, $pkt ) = @_;
    listen_dhcp( $pkt, $user_data );
}

sub listen_dhcp {
    my ( $packet, $eth ) = @_;
    $logger->debug("Received packet on interface");

    my ($l2, $l3, $l4, $dhcp);

    # we need success flag here because we can't next inside try catch
    my $success;
    try {
        ($l2, $l3, $l4, $dhcp) = decompose_dhcp($packet);
        $success = 1;
    } catch {
        $logger->warn("Unable to parse DHCP packet: $_");
    };
    return if (!$success);

    # chaddr filter
    $dhcp->{'chaddr'} = clean_mac( substr( $dhcp->{'chaddr'}, 0, 12 ) );
    return if ( $chaddr_filter && $chaddr_filter ne $dhcp->{'chaddr'});
	
    return if ( !$dhcp->{'options'}{'53'} );

	#Debug raw capture
    $logger->debug( Dumper($l2, $l3, $l4));
    
	# DHCP Message Type filter
    return if ( $type && $type ne $dhcp->{'options'}{'53'} );
    if ($args {'k'}) { 
        $logger->info(POSIX::strftime( "%Y-%m-%d %H:%M:%S", localtime ));
        $logger->info("-" x 80);
        $logger->info(sprintf("Ethernet\tsrc:\t%s\tdst:\t%s", clean_mac($l2->{'src_mac'}), clean_mac($l2->{'dest_mac'})));
        $logger->info(sprintf("IP\t\tsrc: %20s\tdst: %20s", $l3->{'src_ip'}, $l3->{'dest_ip'}));
        $logger->info(sprintf("UDP\t\tsrc port: %15s\tdst port: %15s", $l4->{'src_port'}, $l4->{'dest_port'}));
        $logger->info("-" x 80);
        $logger->info(dhcp_summary($dhcp));
        $logger->debug(Dumper($dhcp));

        foreach my $key ( keys(%{ $dhcp->{'options'} }) ) {
            my $tmpkey = $key;
            $tmpkey = $msg_types{$key} if ( defined( $msg_types{$key} ) );

            my $output;
            if (ref($dhcp->{'options'}{$key}) eq 'ARRAY') {
                $output = join( ",", @{ $dhcp->{'options'}{$key} } );

            } elsif (ref($dhcp->{'options'}{$key}) eq 'SCALAR') {
                $output = ${$dhcp->{'options'}{$key}};

            } elsif (ref($dhcp->{'options'}{$key}) eq 'HASH') {
                $output = Dumper($dhcp->{'options'}{$key});

            } elsif (!ref($dhcp->{'options'}{$key})) {
                $output = $dhcp->{'options'}{$key};
            }
            unless ( !$output ) {
                $logger->info( "$tmpkey: $output" );
            }
        }
        $logger->info("TTL: $l3->{'ttl'}");

        my $dhcp_fingerprint = $dhcp->{'options'}{'55'};
        my $dhcp_vendor = $dhcp->{'options'}{'60'};
        $logger->info("DHCP fingerprint: " . ( defined($dhcp_fingerprint) ? $dhcp_fingerprint : 'None' ));
        $logger->info("DHCP vendor: " . ( defined($dhcp_vendor) ? $dhcp_vendor : 'None' ));

        my $fingerbank_result = fingerbank::api::query($args{k}, {dhcp_fingerprint => $dhcp_fingerprint, dhcp_vendor => $dhcp_vendor});

        if(defined($fingerbank_result)) {
            my $fingerbank_device = join('/', reverse(map {$_->{name}} @{$fingerbank_result->{device}->{parents}})) . '/' . $fingerbank_result->{device}->{name};
            $logger->info("Fingerbank device : $fingerbank_device (".$fingerbank_result->{device}->{id}.")");
            my $fingerbank_version = $fingerbank_result->{version} // 'Unknown';
            $logger->info("Fingerbank device version : ".$fingerbank_version);
            $logger->info("Fingerbank device score : ".$fingerbank_result->{score});
        }
        else {
            $logger->info("Fingerbank device unknown");
        }

        $logger->info("=" x 80);
    }
	if ($args{d}) {
	    $logger->debug( Dumper($l2, $l3, $l4));

    my $hostname =  $dhcp->{'options'}{'12'};
    my $ip_add =  $dhcp->{'options'}{'50'};
    my $dev_score = "0";

    if ( $ip_add  ) {

      $logger->debug("IP ADDRESS: $ip_add");

    #We don't have the IP 
    } else {

      $dev_score = "-1";
      $ip_add = "";

    }

    my $vlan = "UNKNOWN";

    #Pull out vlan tag information, if possible
    {
    no warnings;

      if (($l2->{'tpid'} == 33024) || ($l2->{'tpid'} == 33280) || ($l2->{'tpid'} == 37120)) {

        $vlan = $l2->{'vid'};
        $logger->debug("VLAN ID: $vlan");

      }

    }

    my $dhcp_fingerprint = $dhcp->{'options'}{'55'};
    my $dhcp_vendor = $dhcp->{'options'}{'60'};
    if ($dhcp_fingerprint) {
	$logger->info(POSIX::strftime( "%Y-%m-%d %H:%M:%S", localtime ));
    $logger->info("-" x 80);
	$logger->info("VLAN ID: $vlan");
    $logger->info(sprintf("Ethernet\tsrc:\t%s\tdst:\t%s", clean_mac($l2->{'src_mac'}), clean_mac($l2->{'dest_mac'})));
    $logger->info(sprintf("IP\t\tsrc: %20s\tdst: %20s", $l3->{'src_ip'}, $l3->{'dest_ip'}));
    $logger->info(sprintf("UDP\t\tsrc port: %15s\tdst port: %15s", $l4->{'src_port'}, $l4->{'dest_port'}));
    $logger->info("-" x 80);
      my $dbfile = $dbpath;
      use DBD::SQLite::Constants qw/:file_open/;
      my $dbh = DBI->connect("dbi:SQLite:$dbfile", undef, undef, {

        sqlite_open_flags => SQLITE_OPEN_READONLY,

      });
      my $fingerprint = $dbh->quote("$dhcp_fingerprint");
      my $get_fingerprint_id = "select id from dhcp_fingerprint where value = $fingerprint;";  
      $logger->debug ( $get_fingerprint_id ) ; 
      my $sth_fp = $dbh->prepare($get_fingerprint_id);       
      my $fingerprint_id =  $sth_fp->execute();    
      my $fp_id = $sth_fp->fetchrow_array();
      my $oui = clean_mac($l2->{'src_mac'});
      $oui =~ s/://g;
      my $short_mac = substr( $oui, 0, 6 );
      my $get_mac_id = "select id from mac_vendor where mac = '$short_mac';";
      $logger->debug ( $get_mac_id ) ; 
      my $sth_mac = $dbh->prepare($get_mac_id);
      my $mac_result = $sth_mac->execute();
      my $mac_id = $sth_mac->fetchrow_array();

      if ( $mac_id ) { 

        $logger->debug("MAC ID: $mac_id");

      } else{

        my $mac_id = '-1';

      }

      my $device;
      my $combination_id;
      my $combo_id;

      if ( $mac_id > 0 ) {

        #MAC OUI, DHCP fingerprint and DHCP vendor:
        #The MAC is in the DB, and we have the DHCP fingerprint and DHCP vendor
        if ( $dhcp_vendor ) {

          my $vendor = $dbh->quote("$dhcp_vendor");
          my $get_vendor_id =  "select id from dhcp_vendor where value = $vendor;";
          my $sth_vendor = $dbh->prepare($get_vendor_id);
          my $vendor_result = $sth_vendor->execute();
  	      my $vendor_id = $sth_vendor->fetchrow_array();
          my $get_combination_id ="select device_id,score from combination where dhcp_fingerprint_id = $fp_id and dhcp_vendor_id = $vendor_id and mac_vendor_id = $mac_id order by score DESC limit 1;";
          $logger->debug ( $get_combination_id ) ; 
  	      my $sth_combo = $dbh->prepare($get_combination_id);
          my $combination_result = $sth_combo->execute();
          while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
            $combination_id = $device_id;
            $dev_score = $score;
          }
          {
          no warnings; 
          if ( $combination_id eq "" ) {
            $get_combination_id ="select device_id,score from combination where dhcp_fingerprint_id = $fp_id and dhcp_vendor_id = $vendor_id order by score DESC limit 1;";
            $logger->debug ( $get_combination_id ) ;
            $sth_combo = $dbh->prepare($get_combination_id);
            my $combination_result = $sth_combo->execute();
            while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
              $combination_id = $device_id;
              $dev_score = $score;
            }
            if ( $combination_id eq "" ) {
              $get_combination_id ="select device_id,score from combination where dhcp_fingerprint_id = $fp_id and mac_vendor_id = $vendor_id order by score DESC limit 1;";
              $logger->debug ( $get_combination_id ) ;
              $sth_combo = $dbh->prepare($get_combination_id);
              $combination_result = $sth_combo->execute();
              while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
                $combination_id = $device_id;
                $dev_score = $score;
              }
            }
          }
          }
          my $get_device_name = "select name from device where id = $combination_id order by updated_at DESC;";
          my $sth_device = $dbh->prepare($get_device_name);
          $device = $sth_device->execute();
		  my @client_id = $dhcp->{'options'}{'61'};
          my $dev_name = $sth_device->fetchrow_array();		  
		  $logger->info( 'DHCPREQUEST from ' . $l3->{'src_ip'} . ' (' . $l2->{'src_mac'} . ')');
		  #$logger->info( 'DHCP Client ID: '. join(",", @client_id), "\n");
		  $logger->info( 'requested parameter list: ' . $dhcp->{'options'}{'55'});
		  $logger->info( 'message type: ' . $dhcp->{'options'}{'53'});
		  $logger->info( 'hostname: ' . $dhcp->{'options'}{'12'});
		  $logger->info( 'requested ip address: ' . $ip_add);
		  $logger->info("TTL: $l3->{'ttl'}");
		  $logger->info( 'DHCP fingerprint: ' . $dhcp->{'options'}{'55'});
		  $logger->info( 'DHCP vendor:' . $dhcp->{'options'}{'60'});
		  $logger->info( 'Fingerbank device : ' . $dev_name);
		  $logger->info( 'Fingerbank device score : ' . $dev_score);
        #MAC OUI and DHCP fingerprint:
        #The MAC is in the DB, and we have the DHCP fingerprint but no DHCP vendor
        } else {

          my $get_combination_id = "select device_id,score from combination where dhcp_fingerprint_id = $fp_id and mac_vendor_id = $mac_id order by score DESC limit 1;";
          $logger->debug ( $get_combination_id ) ; 
          my $sth_combo = $dbh->prepare($get_combination_id);
          my $combination_id = $sth_combo->execute();
          while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
            $combo_id = $device_id;
            $dev_score = $score;
          }
          if( $sth_combo->fetchrow_array() ) {

            while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
              $combo_id = $device_id;
              $dev_score = $score;
            }

            my $get_device_name = "select name from device where id = $combo_id order by updated_at DESC;";
            my $sth_device = $dbh->prepare($get_device_name);
            $device = $sth_device->execute();
			my @client_id = $dhcp->{'options'}{'61'};
            my $dev_name = $sth_device->fetchrow_array();
			$logger->info( 'DHCPREQUEST from ' . $l3->{'src_ip'} . ' (' . $l2->{'src_mac'} . ')');
			#$logger->info( 'DHCP Client ID: '. join(",", @client_id), "\n");
			$logger->info( 'requested parameter list: ' . $dhcp->{'options'}{'55'});
			$logger->info( 'message type: ' . $dhcp->{'options'}{'53'});
			$logger->info( 'hostname: ' . $dhcp->{'options'}{'12'});
			$logger->info( 'requested ip address: ' . $ip_add);
			$logger->info("TTL: $l3->{'ttl'}");
			$logger->info( 'DHCP fingerprint: ' . $dhcp->{'options'}{'55'});
			$logger->info( 'DHCP vendor:' . $dhcp->{'options'}{'60'});
			$logger->info( 'Fingerbank device : ' . $dev_name);
			$logger->info( 'Fingerbank device score : ' . $dev_score);
          } else {

            try {

              {
              no warnings;
              my $get_combination_id = "select device_id,score from combination where dhcp_fingerprint_id = $fp_id and mac_vendor_id = $mac_id order by score DESC limit 1;";
              $logger->debug ( $get_combination_id ) ; 
              my $sth_combo = $dbh->prepare($get_combination_id);
              my $combination_id = $sth_combo->execute();
              while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
               $combo_id = $device_id;
               $dev_score = $score;
              }

              if ( $combo_id ne "") {
                $logger->debug( "COMBO ID: $combo_id" );
              } else {
                $combo_id = "0";
              }
              my $get_device_name = "select name from device where id = $combo_id order by updated_at DESC;";
              $logger->debug( $get_device_name );
              my $sth_device = $dbh->prepare($get_device_name);
              $device = $sth_device->execute();
			  my @client_id = $dhcp->{'options'}{'61'};
              my $dev_name = $sth_device->fetchrow_array();
			  $logger->info( 'DHCPREQUEST from ' . $l3->{'src_ip'} . ' (' . $l2->{'src_mac'} . ')');
			  #$logger->info( 'DHCP Client ID: '. join(",", @client_id), "\n");
			  $logger->info( 'requested parameter list: ' . $dhcp->{'options'}{'55'});
			  $logger->info( 'message type: ' . $dhcp->{'options'}{'53'});
			  $logger->info( 'hostname: ' . $dhcp->{'options'}{'12'});
			  $logger->info( 'requested ip address: ' . $ip_add);
			  $logger->info("TTL: $l3->{'ttl'}");
			  $logger->info( 'DHCP fingerprint: ' . $dhcp->{'options'}{'55'});
			  $logger->info( 'DHCP vendor:' . $dhcp->{'options'}{'60'});
			  $logger->info( 'Fingerbank device : ' . $dev_name);
			  $logger->info( 'Fingerbank device score : ' . $dev_score);
              }

            #Combination is not in the DB, use either or:
            } catch {

              {
              no warnings;
              $dev_score = "-1";
              my $get_combination_id = "select device_id,score from combination where dhcp_fingerprint_id = $fp_id or mac_vendor_id = $mac_id order by score DESC limit 1;";
              $logger->debug ( $get_combination_id ) ;
              my $sth_combo = $dbh->prepare($get_combination_id);
              my $combination_id = $sth_combo->execute();
              while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
                $combo_id = $device_id;
                $dev_score = $score;
              }
              my $get_device_name = "select name from device where id = $combo_id order by updated_at DESC;";
              my $sth_device = $dbh->prepare($get_device_name);
              $device = $sth_device->execute();
			  my @client_id = $dhcp->{'options'}{'61'};
              my $dev_name = $sth_device->fetchrow_array();
			  $logger->info( 'DHCPREQUEST from ' . $l3->{'src_ip'} . ' (' . $l2->{'src_mac'} . ')');
			  #$logger->info( 'DHCP Client ID: '. join(",", @client_id), "\n");
			  $logger->info( 'requested parameter list: ' . $dhcp->{'options'}{'55'});
			  $logger->info( 'message type: ' . $dhcp->{'options'}{'53'});
			  $logger->info( 'hostname: ' . $dhcp->{'options'}{'12'});
			  $logger->info( 'requested ip address: ' . $ip_add);
			  $logger->info("TTL: $l3->{'ttl'}");
			  $logger->info( 'DHCP fingerprint: ' . $dhcp->{'options'}{'55'});
			  $logger->info( 'DHCP vendor:' . $dhcp->{'options'}{'60'});
			  $logger->info( 'Fingerbank device : ' . $dev_name);
			  $logger->info( 'Fingerbank device score : ' . $dev_score);
              }

            }

          }

        }

    } else {
    #DHCP fingerprint and DCHP vendor:
    #The MAC in not in the DB, but we have the DHCP fingerprint and DHCP vendor
    if ( $dhcp_vendor ) {

        my $vendor = $dbh->quote("$dhcp_vendor");
        my $get_vendor_id =  "select id from dhcp_vendor where value = $vendor;";
        my $sth_vendor = $dbh->prepare($get_vendor_id);
        my $vendor_result = $sth_vendor->execute();
        my $vendor_id = $sth_vendor->fetchrow_array();
        my $get_combination_id ="select device_id,score from combination where dhcp_fingerprint_id = $fp_id and dhcp_vendor_id = $vendor_id order by score DESC limit 1;";
        $logger->debug ( $get_combination_id ) ; 
        my $sth_combo = $dbh->prepare($get_combination_id);
        my $combination_result = $sth_combo->execute();
        my $combination_id = $sth_combo->fetchrow_array();
        my $get_device_name = "select name from device where id = $combination_id order by updated_at DESC;";
        my $sth_device = $dbh->prepare($get_device_name);
        $device = $sth_device->execute();
		my @client_id = $dhcp->{'options'}{'61'};
        my $dev_name = $sth_device->fetchrow_array();
		$logger->info( 'DHCPREQUEST from ' . $l3->{'src_ip'} . ' (' . $l2->{'src_mac'} . ')');
		#$logger->info( 'DHCP Client ID: '. join(",", @client_id), "\n");
		$logger->info( 'requested parameter list: ' . $dhcp->{'options'}{'55'});
		$logger->info( 'message type: ' . $dhcp->{'options'}{'53'});
		$logger->info( 'hostname: ' . $dhcp->{'options'}{'12'});
		$logger->info( 'requested ip address: ' . $ip_add);
		$logger->info("TTL: $l3->{'ttl'}");
		$logger->info( 'DHCP fingerprint: ' . $dhcp->{'options'}{'55'});
		$logger->info( 'DHCP vendor:' . $dhcp->{'options'}{'60'});
		$logger->info( 'Fingerbank device : ' . $dev_name);
		$logger->info( 'Fingerbank device score : ' . $dev_score);
    #DHCP Fingerprint only:
    #The MAC is not in the DB, we have the DHCP fingerprint but no DHCP vendor
    } else {

        my $get_combination_id = "select device_id,score from combination where dhcp_fingerprint_id = $fp_id order by score DESC limit 1;";
        $logger->debug ( $get_combination_id ) ; 
        my $sth_combo = $dbh->prepare($get_combination_id);
        my $combination_id = $sth_combo->execute();
        while ( my ($device_id, $score) = $sth_combo->fetchrow_array() ) {
          $combo_id = $device_id;
          $dev_score = $score;
        }

        my $get_device_name = "select name from device where id = $combo_id order by updated_at DESC;";
        $logger->debug ( $get_combination_id ) ;
        my $sth_device = $dbh->prepare($get_device_name);
        $device = $sth_device->execute();
		my @client_id = $dhcp->{'options'}{'61'};
        my $dev_name = $sth_device->fetchrow_array();
        $logger->info( 'DHCPREQUEST from ' . $l3->{'src_ip'} . ' (' . $l2->{'src_mac'} . ')');
		#$logger->info( 'DHCP Client ID: '. join(",", @client_id), "\n");
		$logger->info( 'requested parameter list: ' . $dhcp->{'options'}{'55'});
		$logger->info( 'message type: ' . $dhcp->{'options'}{'53'});
		$logger->info( 'hostname: ' . $dhcp->{'options'}{'12'});
		$logger->info( 'requested ip address: ' . $ip_add);
		$logger->info("TTL: $l3->{'ttl'}");
		$logger->info( 'DHCP fingerprint: ' . $dhcp->{'options'}{'55'});
		$logger->info( 'DHCP vendor:' . $dhcp->{'options'}{'60'});
		$logger->info( 'Fingerbank device : ' . $dev_name);
		$logger->info( 'Fingerbank device score : ' . $dev_score);
    }

    }
  }
	$logger->info("-" x 80);
	$logger->info("=" x 80);
	}
}

=head1 AUTHOR

Inverse inc.

=head1 COPYRIGHT

Copyright (C) 2009-2016 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

