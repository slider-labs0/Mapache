#!/bin/bash
# Provision a small Active Directory domain on first boot, then run the DC in the
# foreground. Seeds a kerberoastable service account (svc_sql) with an SPN and a
# weak, dictionary password, plus a low-privileged user the assessor authenticates
# as. No CTF flag - the finding is the kerberoastable account + weak service password.
set -eu

REALM="CORP.LOCAL"
DOMAIN="CORP"

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --use-rfc2307 \
        --realm "$REALM" \
        --domain "$DOMAIN" \
        --server-role dc \
        --dns-backend SAMBA_INTERNAL \
        --adminpass 'Adm1nP@ssw0rd!'

    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

    # A normal low-priv user the assessor logs in as (given in the task).
    samba-tool user create lowpriv 'LowPriv1!'

    # The kerberoastable service account: has an SPN and a weak password that any
    # authenticated user can request a crackable TGS for.
    samba-tool user create svc_sql 'Summer2021'
    samba-tool spn add "MSSQLSvc/sql01.$REALM:1433" svc_sql

    # Prefer RC4 for svc_sql's service ticket so the $krb5tgs$23$ hash is offline-
    # crackable (the classic kerberoast), independent of the domain default.
    samba-tool user setpassword svc_sql --newpassword 'Summer2021' >/dev/null 2>&1 || true
fi

exec samba -i --debug-stdout
