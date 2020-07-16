#!/usr/bin/env bash
set -x

function print_help() {
    cat <<EOF
                Docker SMF - Simple Mail Forwarder
===============================================================================
To create a new mail server for your domain,
you could use the following commands:

$ docker run -p 25:25 \\
    zixia/simple-mail-forwarder \\
    user1@domain1.com:forward-user1@forward-domain1.com; \\
    user2@domain1.com:forward-user2@forward-domain1.com; \\
    userN@domainN.com:forward-userN@forward-domainN.com;

Environment Variables:
    SMF_DOMAIN - mail server hostname. use tutum/docker hostname if omitted.
    SMF_CONFIG - mail forward addresses mapping list.
    SMF_MYNETWORKS - configure relaying from trusted IPs, see http://www.postfix.org/postconf.5.html#mynetworks
    SMF_RELAYHOST - configure a relayhost

this creates a new smtp server which listens on port 25,
forward all email from
userN@domainN.com to forward-userN@forward-domainN.com
_______________________________________________________________________________

EOF
}

function init_config() {
    if ! /usr/bin/env python3 /install/init-config.py; then
        print_help
        return 1
    fi
}

#
# TEST
#
function test_running_env() {
    echo ">> Start self-testing..."

    if bats test/simple-mail-forwarder.bats; then
        echo ">> Test PASSED"
    else
        echo ">> Test FAILED!"

        echo ">> !!!!!!!!!!!!!!!!!!!! SYSTEM ERROR !!!!!!!!!!!!!!!!!!!!"
        echo ">> !!!!!!!!!!!!!!!!!!!! SYSTEM ERROR !!!!!!!!!!!!!!!!!!!!"
        echo ">> !!!!!!!!!!!!!!!!!!!! SYSTEM ERROR !!!!!!!!!!!!!!!!!!!!"

        echo ">> But I'll pretend to run... good luck! :P"
    fi
}

echo ">> Chdir to /app..."
cd /app || exit 1

# shellcheck disable=SC1091
[ -e BUILD.env ] && source BUILD.env
echo "SMF_DOMAIN='$HOSTNAME'" > SMF_DOMAIN.env
echo "SMF_CONFIG='$SMF_CONFIG'" > SMF_CONFIG.env

echo "dns_cloudflare_api_token = ${CLOUDFLARE_DNS_API_TOKEN}" > /install/CLOUDFLARE_DNS_API_TOKEN

# Generated by figlet
cat BANNER

echo
echo ">> Powered by SMF - a Simple Mail Forwarder"
echo ">> View in DockerHub: https://hub.docker.com/r/zixia/simple-mail-forwarder"
echo

init_config || exit 1

if [ "$1" == "start" ]; then
    exec /sbin/my_init
elif [ "$1" == "help" ]; then
    print_help
elif [ "$1" == "test" ]; then
    test_running_env
else
    exec /sbin/my_init
fi