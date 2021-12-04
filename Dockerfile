#Dockerfile for a Postfix email relay service
FROM alpine:3.15
MAINTAINER Juan Luis Baptiste juan.baptiste@gmail.com

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

EXPOSE 25 587
#ENTRYPOINT ["/run.sh"]
CMD ["/run.sh"]
