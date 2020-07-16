#!/usr/bin/env bash

set -x

PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
export PATH

# guess path for command_directory
command_directory=$(postconf -h command_directory)
daemon_directory=$("$command_directory/postconf" -h daemon_directory)

# kill Postfix if running
"$daemon_directory/master" -t || "$command_directory/postfix" stop

# sv start opendkim || exit 1
# run Postfix
# exec "$daemon_directory/master"
exec "$command_directory/postfix" start-fg
