#!/usr/bin/env bash

set -x

PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
export PATH
exec "$(which opendkim)" -x /etc/opendkim.conf -f -p /var/spool/postfix/opendkim/opendkim.sock