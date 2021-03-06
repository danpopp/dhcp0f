package fingerbank::api;

=head1 NAME

fingerbank::api

=cut

=head1 DESCRIPTION

Module to query the Fingerbank API

=cut

use JSON;
use URI;
use LWP::UserAgent;
use HTTP::Request;

sub query {
    my ($key, $params) = @_;
    my $logger = Log::Log4perl->get_logger('');                                                                             

    my $ua = LWP::UserAgent->new;
    $ua->timeout(2);   # An interrogate query should not take more than 2 seconds
    my $query_args = encode_json($params);

    my %parameters = ( key => $key );
    my $url = URI->new("https://fingerbank.inverse.ca/api/v1/combinations/interrogate");
    $url->query_form(%parameters);

    my $req = HTTP::Request->new( GET => $url->as_string);
    $req->content_type('application/json');
    $req->content($query_args);

    my $res = $ua->request($req);

    if ( $res->is_success ) {
        my $result = decode_json($res->content);
        $logger->debug("Successfully interrogate upstream Fingerbank project for matching. Got device : ".$result->{device}->{id});
        return $result;
    } else {
        $logger->debug("An error occured while interrogating upstream Fingerbank project: " . $res->status_line);
        return undef;
    }

}

=back

=head1 AUTHOR

Inverse inc.

=head1 COPYRIGHT

Copyright (C) 2011-2016 Inverse inc.

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

1;
