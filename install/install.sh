#!/usr/bin/env bash

set -x

# disable sshd
rm -rf /etc/service/sshd

mv /install/entrypoint.sh /app/entrypoint.sh
chmod +x /app/entrypoint.sh

# syslog-ng.conf manipulation
sed -i 's/@version.*$/@version:\ 3.25/g' /etc/syslog-ng/syslog-ng.conf
sed -i 's/use_dns\(no\);//g' /etc/syslog-ng/syslog-ng.conf

mkdir -p /etc/postfix/cert

mv /install/main.dist.cf /etc/postfix/main.cf
mv /install/master.dist.cf /etc/postfix/master.cf

mv /install/smtp_header_checks /etc/postfix/smtp_header_checks

# init postfix config
cat /dev/null > /etc/postfix/aliases && newaliases \
    && echo simple-mail-forwarder.com > /etc/hostname \
    && echo test | saslpasswd2 -p test@test.com \
    && chown postfix /etc/sasldb2 \
    && saslpasswd2 -d test@test.com

mv /install/BANNER /app/
mv /install/buildenv.sh /app/
chmod +x /app/buildenv.sh

chmod +x /install/init-config.py
chmod +x /install/gen-cert-openssl.sh

mkdir -p /etc/service/postfix
mv /install/postfix.sh /etc/service/postfix/run
chmod +x /etc/service/postfix/run

mkdir -p /etc/cron.d
mv /install/cron-certbot /etc/cron.d/certbot

echo "dns_cloudflare_api_token = ${CLOUDFLARE_DNS_API_TOKEN}" > /install/CLOUDFLARE_DNS_API_TOKEN
chmod 600 /install/CLOUDFLARE_DNS_API_TOKEN

adduser postfix opendkim

mkdir -p /etc/service/opendkim
mv /install/opendkim.sh /etc/service/opendkim/run
chmod +x /etc/service/opendkim/run

mv /install/opendkim.conf /etc/opendkim.conf
chmod u=rw,go=r /etc/opendkim.conf
mkdir -p /etc/opendkim/keys
chown -R opendkim:opendkim /etc/opendkim
chmod go-rw /etc/opendkim/keys

mkdir -p /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim
# original SOCKET=local:$RUNDIR/opendkim.sock
sed -i 's%^.*SOCKET=.*local.*$%SOCKET=\"local:/var/spool/postfix/opendkim/opendkim.sock\"%g' /etc/default/opendkim

# clean
rm -rf ~/.cache ~/.bash_history
bash /bd_build/cleanup.sh