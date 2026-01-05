$ORIGIN com.
$TTL 3600
com. IN SOA ns.com. admin.com. 1719172701 7200 3600 1209600 3600
com. IN A 192.0.2.1
com. IN AAAA 2001:db8::1 
com. IN MX 10 mail.net.
com. IN TXT "This zone is an example input for PQC zone signing"
com. IN CNAME com.
com. IN NS ns1.net.
com. IN NS ns2.net.
