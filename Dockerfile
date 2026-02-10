#Dockerfile for a Postfix email relay service
FROM alpine:3.23
LABEL org.opencontainers.image.authors="juan@juanbaptiste.tech"

# Latest versions available on 2026-02-10:
# v3.23: 3.10.7-r0
# https://pkgs.alpinelinux.org/packages?name=postfix&branch=v3.23

ARG POSTFIX_VERSION=3.10.7-r0

RUN apk update && \
    apk add bash gawk cyrus-sasl cyrus-sasl-login cyrus-sasl-crammd5 cyrus-sasl-gssapiv2 \
    supervisor postfix postfix-ldap postfix-pcre rsyslog krb5 && \
    rm -rf /var/cache/apk/* && \
    mkdir -p /var/log/supervisor/ /var/run/supervisor/ && \
    sed -i -e 's/inet_interfaces = localhost/inet_interfaces = all/g' /etc/postfix/main.cf

COPY etc/ /etc/
COPY run.sh /
RUN chmod +x /run.sh && \
    newaliases

EXPOSE 25
#ENTRYPOINT ["/run.sh"]
CMD ["/run.sh"]
