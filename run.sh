#!/bin/bash

[ "${DEBUG}" == "yes" ] && set -x

function add_config_value() {
  local key=${1}
  local value=${2}
  # local config_file=${3:-/etc/postfix/main.cf}
  [ "${key}" == "" ] && echo "ERROR: No key set !!" && exit 1
  [ "${value}" == "" ] && echo "ERROR: No value set !!" && exit 1

  echo "Setting configuration option ${key} with value: ${value}"
 postconf -e "${key} = ${value}"
}

# Read password from file to avoid unsecure env variables
if [ -n "${SMTP_PASSWORD_FILE}" ]; then [ -f "${SMTP_PASSWORD_FILE}" ] && read SMTP_PASSWORD < ${SMTP_PASSWORD_FILE} || echo "SMTP_PASSWORD_FILE defined, but file not existing, skipping."; fi

if [ -z "${SMTP_SERVER}" -a -z "${TRANSPORT_MAP_FILE}" ]; then
    echo "no SMTP_SERVER and no ${TRANSPORT_MAP_FILE} is set; exit"
    exit 1
fi
[ -z "${SERVER_HOSTNAME}" ] && echo "SERVER_HOSTNAME is not set" && exit 1
[ ! -z "${SMTP_USERNAME}" -a -z "${SMTP_PASSWORD}" ] && echo "SMTP_USERNAME is set but SMTP_PASSWORD is not set" && exit 1

SMTP_PORT="${SMTP_PORT:-587}"
INET_INTERFACES="${INET_INTERFACES:-all}"
INET_PROTOCOLS="${INET_PROTOCOLS:-all}"

#Get the domain from the server host name
if [ -z "${SERVER_DOMAIN}" ]; then
    SERVER_DOMAIN=`echo ${SERVER_HOSTNAME} | awk 'BEGIN{FS=OFS="."}{print $(NF-1),$NF}'`
fi
# Set needed config options

add_config_value "inet_interfaces" "${INET_INTERFACES}"
add_config_value "inet_protocols" "${INET_PROTOCOLS}"
add_config_value "myhostname" "${SERVER_HOSTNAME}"
add_config_value "mydomain" "${SERVER_DOMAIN}"
add_config_value "mydestination" 'localhost'
add_config_value "myorigin" '$mydomain'
if [ -z "${SMTP_SERVER}" ]; then
    postconf -e "relayhost ="
else
    add_config_value "relayhost" "[${SMTP_SERVER}]:${SMTP_PORT}"
fi
postconf -e "relay_domains = ${RELAY_DOMAINS}"
if [ ! -z "${SMTP_BIND_ADDRESS}" ]; then
    add_config_value "smtp_bind_address" "${SMTP_BIND_ADDRESS}"
fi
add_config_value "smtp_use_tls" "yes"
if [ ! -z "${SMTP_USERNAME}" -o ! -z "${SASL_PASSWD_FILE}" ]; then
  add_config_value "smtp_sasl_auth_enable" "yes"
  add_config_value "smtp_sasl_password_maps" "lmdb:/etc/postfix/sasl_passwd"
  add_config_value "smtp_sasl_security_options" "noanonymous"
  add_config_value "smtp_sasl_mechanism_filter" "login,plain"
fi
add_config_value "always_add_missing_headers" "${ALWAYS_ADD_MISSING_HEADERS:-no}"
#Also use "native" option to allow looking up hosts added to /etc/hosts via
# docker options (issue #51)
add_config_value "smtp_host_lookup" "native,dns"

if [ "${SMTP_PORT}" = "465" ]; then
  add_config_value "smtp_tls_wrappermode" "yes"
  add_config_value "smtp_tls_security_level" "encrypt"
fi

if [ ! -z "${MASQUERADE_DOMAINS}" ]; then
  add_config_value "masquerade_classes" "envelope_sender,header_sender,header_recipient"
  add_config_value "masquerade_domains" "${MASQUERADE_DOMAINS}"
  add_config_value "masquerade_exceptions" "root"
fi

if [ ! -z "${SMTP_CERT_FILE}" ]; then
    cp "${SMTP_CERT_FILE}" /etc/postfix/smtpd_cert.pem
    chmod 0644 /etc/postfix/smtpd_cert.pem
    chown root.root /etc/postfix/smtpd_cert.pem
    postconf -e "smtpd_tls_cert_file = /etc/postfix/smtpd_cert.pem"
fi
if [ ! -z "${SMTP_KEY_FILE}" ]; then
    cp "${SMTP_KEY_FILE}" /etc/postfix/smtpd_key.pem
    chmod 0600 /etc/postfix/smtpd_key.pem
    chown root.root /etc/postfix/smtpd_key.pem
    postconf -e "smtpd_tls_key_file = /etc/postfix/smtpd_key.pem"
fi

if [ "${ENABLE_SUBMISSION}" = "true" ]; then
    postconf -e "smtp_tls_wrappermode=no"
    postconf -e "smtp_tls_security_level=encrypt"

    if [ ! -f "/etc/postfix/master.cf.org" ]; then
        cp "/etc/postfix/master.cf" "/etc/postfix/master.cf.org"
    fi
    cp "/etc/postfix/master.cf.org" "/etc/postfix/master.cf"
    echo "Enable submission support"
        cat >> "/etc/postfix/master.cf" <<EOF
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
EOF

fi

# Create sasl_passwd file with auth credentials
if [ ! -z "${SASL_PASSWD_FILE}" ]; then
    cp "${SASL_PASSWD_FILE}" /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
elif [ ! -f /etc/postfix/sasl_passwd -a ! -z "${SMTP_USERNAME}" ]; then
  grep -q "${SMTP_SERVER}" /etc/postfix/sasl_passwd  > /dev/null 2>&1
  if [ $? -gt 0 ]; then
    echo "Adding SASL authentication configuration"
    echo "[${SMTP_SERVER}]:${SMTP_PORT} ${SMTP_USERNAME}:${SMTP_PASSWORD}" >> /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
  fi
fi

#Set header tag
if [ ! -z "${SMTP_HEADER_TAG}" ]; then
  postconf -e "header_checks = regexp:/etc/postfix/header_tag"
  echo -e "/^MIME-Version:/i PREPEND RelayTag: $SMTP_HEADER_TAG\n/^Content-Transfer-Encoding:/i PREPEND RelayTag: $SMTP_HEADER_TAG" > /etc/postfix/header_tag
  echo "Setting configuration option SMTP_HEADER_TAG with value: ${SMTP_HEADER_TAG}"
fi

#Check for subnet restrictions
nets='10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'
if [ ! -z "${SMTP_NETWORKS}" ]; then
        for i in $(sed 's/,/\ /g' <<<$SMTP_NETWORKS); do
                if grep -Eq "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}" <<<$i ; then
                        nets+=", $i"
                else
                        echo "$i is not in proper IPv4 subnet format. Ignoring."
                fi
        done
fi
add_config_value "mynetworks" "${nets}"

if [ ! -z "${OVERWRITE_FROM}" ]; then
  echo -e "/^From:.*$/ REPLACE From: $OVERWRITE_FROM" > /etc/postfix/smtp_header_checks
  postmap /etc/postfix/smtp_header_checks
  postconf -e 'smtp_header_checks = regexp:/etc/postfix/smtp_header_checks'
  echo "Setting configuration option OVERWRITE_FROM with value: ${OVERWRITE_FROM}"
fi

if [ ! -z "${RELAY_RECIPIENT_MAP_FILE}" ]; then
    cp "${RELAY_RECIPIENT_MAP_FILE}" /etc/postfix/relay_recipient
    postmap lmdb:/etc/postfix/relay_recipient
    postconf -e 'relay_recipient_maps = lmdb:/etc/postfix/relay_recipient'
fi

if [ ! -z "${TRANSPORT_MAP_FILE}" ]; then
    cp "${TRANSPORT_MAP_FILE}" /etc/postfix/transport
    postmap lmdb:/etc/postfix/transport
    postconf -e 'transport_maps = lmdb:/etc/postfix/transport'
fi

if [ ! -z "${RECIPIENT_CANONICAL_MAP_FILE}" ]; then
    cp "${RECIPIENT_CANONICAL_MAP_FILE}" /etc/postfix/recipient_canonical
    postmap lmdb:/etc/postfix/recipient_canonical
    postconf -e 'recipient_canonical_maps = lmdb:/etc/postfix/recipient_canonical'
fi

if [ ! -z "${SENDER_CANONICAL_MAP_FILE}" ]; then
    cp "${SENDER_CANONICAL_MAP_FILE}" /etc/postfix/sender_canonical
    postmap lmdb:/etc/postfix/sender_canonical
    postconf -e 'sender_canonical_maps = lmdb:/etc/postfix/sender_canonical'
fi

if [ ! -z "${SENDER_LOGIN_MAP_FILE}" ]; then
    cp "${SENDER_LOGIN_MAP_FILE}" /etc/postfix/sender_login
    if [ "${SENDER_LOGIN_LDAP}" = "true" ]; then
        chown postfix.mail /etc/postfix/sender_login
        postconf -e 'smtpd_sender_login_maps = proxy:ldap:/etc/postfix/sender_login'
    else
        postmap lmdb:/etc/postfix/sender_login
        postconf -e 'smtpd_sender_login_maps = lmdb:/etc/postfix/sender_login'
    fi
fi

if [ ! "${SASLAUTHD_AUTHMECH}" = "pam" ]; then
    echo "Remove saslauthd-pam from supervisord"
    rm /etc/supervisord.d/saslauthd-pam.ini
fi
if [ ! "${SASLAUTHD_AUTHMECH}" = "krb5" ]; then
    echo "Remove saslauthd-krb5 from supervisord"
    rm /etc/supervisord.d/saslauthd-krb5.ini
fi

if [ ! -z "${KRB5_KEYTAB_FILE}" ]; then
    cp "${KRB5_KEYTAB_FILE}" /etc/krb5.keytab
    chown postfix.mail /etc/krb5.keytab
    chmod 0600 /etc/krb5.keytab
fi

# create dir for saslauthd
[ ! -d /var/spool/postfix/var/run ] && mkdir -p /var/spool/postfix/var/run

if [ ! -z "${SASLAUTHD_CONF_FILE}" ]; then
    mkdir /etc/postfix/sasl
    cp "${SASLAUTHD_CONF_FILE}" /etc/postfix/sasl/smtpd.conf
fi

#Start services

# If host mounting /var/spool/postfix, we need to delete old pid file before
# starting services
rm -f /var/spool/postfix/pid/master.pid

exec supervisord -c /etc/supervisord.conf
