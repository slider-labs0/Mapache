# Live Active Directory Domain Controller (Samba AD DC) with a kerberoastable
# service account. Heavier than the stdlib targets; provisions on first boot.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        samba smbclient krb5-user winbind ldb-tools \
        libnss-winbind libpam-winbind ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY app/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, DNS 53.
EXPOSE 53 88 389 445 464 636
CMD ["/usr/local/bin/entrypoint.sh"]
