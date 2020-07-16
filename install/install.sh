#!/usr/bin/env bash

set -x

# disable sshd
rm -rf /etc/service/sshd

# syslog-ng.conf manipulation
sed -i 's/@version.*$/@version:\ 3.25/g' /etc/syslog-ng/syslog-ng.conf
sed -i 's/use_dns(no);//g' /etc/syslog-ng/syslog-ng.conf

chmod +x /app/entrypoint.sh

mkdir -p /etc/postfix/cert

mv /app/main.dist.cf /etc/postfix/main.cf
mv /app/master.dist.cf /etc/postfix/master.cf

mv /app/smtp_header_checks /etc/postfix/smtp_header_checks

mv /app/BANNER /app/

chmod +x /app/init-config.py
chmod +x /app/gen-cert-openssl.sh

mkdir -p /etc/service/postfix
mv /app/postfix.sh /etc/service/postfix/run
chmod +x /etc/service/postfix/run

mkdir -p /etc/cron.d
mv /app/cron-certbot /etc/cron.d/certbot

adduser postfix opendkim

mkdir -p /etc/service/opendkim
mv /app/opendkim.sh /etc/service/opendkim/run
chmod +x /etc/service/opendkim/run

mv /app/opendkim.conf /etc/opendkim.conf
chmod u=rw,go=r /etc/opendkim.conf
mkdir -p /etc/opendkim/keys
chown -R opendkim:opendkim /etc/opendkim
chmod go-rw /etc/opendkim/keys

mkdir -p /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim
# original SOCKET=local:$RUNDIR/opendkim.sock
sed -i 's%^\s*SOCKET=.*$%%g' /etc/default/opendkim
sed -i 's%^\s*RUNDIR=.*$%%g' /etc/default/opendkim
sed  -i '1i SOCKET="local:/var/spool/postfix/opendkim/opendkim.sock"' /etc/default/opendkim
sed  -i '1i RUNDIR="/var/spool/postfix/opendkim"' /etc/default/opendkim

postconf -e daemon_directory="/usr/lib/postfix/sbin"

# clean
rm -rf ~/.cache ~/.bash_history
bash /bd_build/cleanup.sh