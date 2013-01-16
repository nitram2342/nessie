#!/bin/sh

(echo;echo) | openssl s_client -host 127.0.0.1 -showcerts -port 8834 
