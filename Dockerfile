FROM phusion/baseimage:focal-1.0.0alpha1-amd64

LABEL maintainer="tinkernels <don.johnny.cn@gmail.com>"

COPY install /install
COPY test /app/test
COPY .git/logs/HEAD /app/GIT_LOG
COPY .git/HEAD /app/GIT_HEAD

WORKDIR /app

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && \
    apt-get install -qy software-properties-common && add-apt-repository -y universe && \
    apt-get update && apt-get upgrade -y -o Dpkg::Options::="--force-confold" && \
    install_clean tzdata bats sasl2-bin libsasl2-2 libsasl2-dev libsasl2-modules ldnsutils python3-pip \
    postfix opendkim opendkim-tools postfix-policyd-spf-python postfix-pcre && \
    pip3 install -U pyyaml certbot acme certbot-dns-cloudflare && chmod +x /install/install.sh

RUN /install/install.sh

VOLUME ["/var/spool/postfix"]

EXPOSE 25

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["start"]

