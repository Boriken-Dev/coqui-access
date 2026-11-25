#!/bin/bash
# Starts a KDC for EXAMPLE.TEST and a slapd for dc=example,dc=test.
#
# Mounted by the test:  /in   (read-only)  ca.pem server.pem server.key
#                       /out  (read-write) receives svc.keytab, then the file `ready`
#                       /sock (read-write) receives the ldapi socket `ldapi`
# Environment:          ADMIN_PW (directory manager), ANA_PW (the person `ana`)
# The service principals are ldap/ldap.example.test (slapd) and svc (the client's keytab).
set -eu
REALM=EXAMPLE.TEST
HOST=ldap.example.test
BASE="dc=example,dc=test"

cat > /etc/krb5.conf <<KRB
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  dns_canonicalize_hostname = false
[realms]
  $REALM = {
    kdc = 127.0.0.1:88
  }
[domain_realm]
  .example.test = $REALM
KRB
mkdir -p /var/kerberos/krb5kdc
cat > /var/kerberos/krb5kdc/kdc.conf <<KDC
[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88
[realms]
  $REALM = {
    acl_file = /var/kerberos/krb5kdc/kadm5.acl
  }
KDC
kdb5_util create -s -r $REALM -P "$(head -c 24 /dev/urandom | base64)" >/dev/null
kadmin.local -q "addprinc -randkey ldap/$HOST" >/dev/null
kadmin.local -q "ktadd -k /etc/krb5.keytab ldap/$HOST" >/dev/null
kadmin.local -q "addprinc -randkey svc" >/dev/null
kadmin.local -q "ktadd -k /out/svc.keytab svc" >/dev/null
chmod 644 /out/svc.keytab
krb5kdc

SLAPD=/etc/openldap/slapd-test.conf
cat > $SLAPD <<CONF
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
pidfile /run/slapd.pid
TLSCACertificateFile /in/ca.pem
TLSCertificateFile /in/server.pem
TLSCertificateKeyFile /in/server.key
TLSVerifyClient allow
sasl-realm $REALM
sasl-host $HOST
# The Kerberos principal svc@EXAMPLE.TEST is the entry uid=svc; a client certificate whose
# common name is extsvc, and the process behind the ldapi socket (uid 0 as the container sees
# it), are mapped the same way.
authz-regexp "^uid=svc,cn=example.test,cn=gssapi,cn=auth\$" "uid=svc,ou=people,$BASE"
authz-regexp "^(.*,)?cn=extsvc(,.*)?$" "uid=extsvc,ou=people,$BASE"
authz-regexp "^gidNumber=0.uidNumber=0,cn=peercred,cn=external,cn=auth$" "uid=sock,ou=people,$BASE"
# Simple binds need a confidential channel: ldaps, StartTLS or a sealed SASL layer. This is
# the signing requirement of a hardened Active Directory domain controller.
security simple_bind=128
database mdb
suffix "$BASE"
rootdn "cn=admin,$BASE"
rootpw $(slappasswd -s "$ADMIN_PW")
directory /var/lib/ldap-test
index objectClass eq
access to attrs=userPassword by anonymous auth by * none
access to * by users read by * none
CONF
mkdir -p /var/lib/ldap-test /run/ldapi
slapd -f $SLAPD -h "ldap://0.0.0.0:389/ ldaps://0.0.0.0:636/ ldapi://%2Fsock%2Fldapi/"

# slapd answers once the socket exists; load the entries as the directory manager.
export LDAPTLS_CACERT=/in/ca.pem
for _ in $(seq 1 100); do
  ldapwhoami -x -H ldaps://localhost:636 >/dev/null 2>&1 && break
  sleep 0.1
done
LDAPTLS_CACERT=/in/ca.pem ldapadd -x -H ldaps://localhost:636 -D "cn=admin,$BASE" -y <(printf %s "$ADMIN_PW") >/dev/null <<LDIF
dn: $BASE
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: ou=people,$BASE
objectClass: organizationalUnit
ou: people

dn: uid=svc,ou=people,$BASE
objectClass: inetOrgPerson
uid: svc
cn: Service
sn: Service

dn: uid=extsvc,ou=people,$BASE
objectClass: inetOrgPerson
uid: extsvc
cn: Certificate Service
sn: Service

dn: uid=sock,ou=people,$BASE
objectClass: inetOrgPerson
uid: sock
cn: Socket Service
sn: Service

dn: uid=ana,ou=people,$BASE
objectClass: inetOrgPerson
uid: ana
cn: Ana Rivera
sn: Rivera
mail: ana@example.test
userPassword: $(slappasswd -s "$ANA_PW")

dn: cn=operators,ou=people,$BASE
objectClass: groupOfNames
cn: operators
member: uid=ana,ou=people,$BASE
LDIF
chmod 777 /sock
chmod 666 /sock/ldapi
touch /out/ready
exec sleep infinity
