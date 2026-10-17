"""
Remediation database – mapping from check_id to fix instructions.
"""

REMEDIATION_MAP = {
    # Web Engine (1-28)
    1: {
        "fix": "Close unnecessary ports on the firewall. Only ports 80 and 443 should be open.",
        "example": "iptables -A INPUT -p tcp --dport 80 -j ACCEPT; iptables -A INPUT -p tcp --dport 443 -j ACCEPT; iptables -A INPUT -j DROP",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Test_HTTP_Methods"
    },
    2: {
        "fix": "Redirect all HTTP traffic to HTTPS using a 301 redirect.",
        "example": "Redirect permanent / https://example.com/",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
    },
    3: {
        "fix": "Ensure HTTPS is properly configured with a valid certificate. Check certificate chain and renewal.",
        "reference": "https://www.ssllabs.com/ssltest/"
    },
    4: {
        "fix": "Disable server version banner. Hide version in Server header.",
        "example": "ServerTokens Prod (Apache) or server_tokens off; (Nginx)",
        "reference": "https://geekflare.com/important-http-headers/"
    },
    5: {
        "fix": "Remove or obfuscate headers that disclose software versions (X-Powered-By, X-AspNet-Version, etc.).",
        "example": "expose_php = Off (PHP) or <httpRuntime enableVersionHeader=\"false\" /> (ASP.NET)",
        "reference": "https://www.acunetix.com/blog/articles/disclosing-web-server-version/"
    },
    6: {
        "fix": "Configure ETag to be a strong opaque hash to avoid leaking inode information.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag"
    },
    7: {
        "fix": "Enable X-XSS-Protection header.",
        "example": "X-XSS-Protection: 1; mode=block",
        "reference": "https://owasp.org/www-project-secure-headers/#x-xss-protection"
    },
    8: {
        "fix": "Add X-Frame-Options header to prevent clickjacking. Use DENY or SAMEORIGIN.",
        "example": "X-Frame-Options: SAMEORIGIN",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    9: {
        "fix": "Implement HTTP Strict Transport Security (HSTS). Include all subdomains and consider preload.",
        "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "reference": "https://hstspreload.org/"
    },
    10: {
        "fix": "Add a Content-Security-Policy header to mitigate XSS and data injection.",
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self'",
        "reference": "https://content-security-policy.com/"
    },
    11: {
        "fix": "Set HttpOnly and Secure flags on all cookies. Also consider SameSite=Strict or Lax.",
        "example": "Set-Cookie: sessionid=...; HttpOnly; Secure; SameSite=Strict",
        "reference": "https://owasp.org/www-community/HttpOnly"
    },
    12: {
        "fix": "Set SameSite attribute on cookies to either Strict or Lax to prevent CSRF.",
        "example": "Set-Cookie: sessionid=...; SameSite=Lax",
        "reference": "https://web.dev/samesite-cookies-explained/"
    },
    13: {
        "fix": "Set Cache-Control headers to prevent sensitive content from being cached.",
        "example": "Cache-Control: no-cache, no-store, must-revalidate",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
    },
    14: {
        "fix": "Disable unnecessary HTTP methods (PUT, DELETE, TRACE, OPTIONS) unless required.",
        "example": "Limit except GET HEAD POST in Apache; return 405 for disallowed methods.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Test_HTTP_Methods"
    },
    15: {
        "fix": "Restrict access to admin/login interfaces to internal IPs or VPN. Use .htaccess or firewall rules.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
    },
    16: {
        "fix": "Disable SSLv2, SSLv3, and TLSv1.0 on your server. Use only TLSv1.2 and TLSv1.3.",
        "example": "SSLProtocol –ALL +TLSv1.2 +TLSv1.3 (Apache)",
        "reference": "https://www.ssllabs.com/ssltest/"
    },
    17: {
        "fix": "Disable weak ciphers (RC4, DES, 3DES, etc.). Use modern AEAD ciphers like AES-GCM.",
        "example": "SSLCipherSuite HIGH:!aNULL:!MD5:!3DES (Apache)",
        "reference": "https://wiki.mozilla.org/Security/Server_Side_TLS"
    },
    18: {
        "fix": "POODLE attack is mitigated by disabling SSLv3. Ensure no SSLv3 support.",
        "reference": "https://www.openssl.org/~bodo/ssl-poodle.pdf"
    },
    19: {
        "fix": "Logjam attack – disable DHE_EXPORT ciphers and use strong DH parameters (≥2048 bits).",
        "reference": "https://weakdh.org/"
    },
    20: {
        "fix": "Heartbleed – upgrade OpenSSL to a patched version (≥1.0.1g).",
        "reference": "https://heartbleed.com/"
    },
    21: {
        "fix": "CRIME attack – disable TLS compression. Ensure compression is off.",
        "reference": "https://en.wikipedia.org/wiki/CRIME"
    },
    22: {
        "fix": "CCS Injection – upgrade OpenSSL to a version that fixes CVE-2014-0224.",
        "reference": "https://ccsinjection.lepidum.co.jp/"
    },
    23: {
        "fix": "Anonymous cipher vulnerability – disable anonymous (aNULL) ciphers.",
        "example": "SSLCipherSuite HIGH:!aNULL",
        "reference": "https://www.openssl.org/docs/manmaster/man1/ciphers.html"
    },
    24: {
        "fix": "FREAK attack – disable EXPORT ciphers and use a modern OpenSSL version.",
        "reference": "https://freakattack.com/"
    },
    25: {
        "fix": "DROWN attack – ensure SSLv2 is completely disabled on all servers sharing the same certificate.",
        "reference": "https://drownattack.com/"
    },
    26: {
        "fix": "Enable forward secrecy by using ECDHE or DHE cipher suites.",
        "example": "SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM",
        "reference": "https://wiki.mozilla.org/Security/Server_Side_TLS"
    },
    27: {
        "fix": "Block HTTP/1.0 requests if not needed, or ensure they respond correctly.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Evolution_of_HTTP"
    },
    28: {
        "fix": "Publish CAA records to restrict which CAs can issue certificates for your domain.",
        "example": "example.com. IN CAA 0 issue \"pki.goog\"",
        "reference": "https://sslmate.com/caa/"
    },

    # DNS Engine (29-40)
    29: {
        "fix": "Only DNS port (53) should be open. Close any other ports on the DNS server.",
        "reference": "https://www.cyberciti.biz/faq/unix-linux-etc-services-file-explained/"
    },
    30: {
        "fix": "Hide DNS server version by configuring 'version none;' in BIND or equivalent in other servers.",
        "example": "options { version none; };",
        "reference": "https://kb.isc.org/docs/aa-00369"
    },
    31: {
        "fix": "Disable recursion for external clients. Use 'allow-recursion' to restrict to trusted networks.",
        "example": "options { recursion no; };",
        "reference": "https://www.isc.org/bind/"
    },
    32: {
        "fix": "Ensure source port and transaction ID are random. This is usually default in modern DNS servers.",
        "reference": "https://tools.ietf.org/html/rfc5452"
    },
    33: {
        "fix": "Implement DNSSEC by signing your zone and publishing DS records at the registrar.",
        "reference": "https://dnssec-deployment.org/"
    },
    34: {
        "fix": "Use RSA/SHA-256 (algorithm 8) for DNSSEC keys; avoid deprecated algorithms.",
        "reference": "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml"
    },
    35: {
        "fix": "Prevent NSEC walking by using NSEC3 with salt and opt-out.",
        "example": "dnssec-policy default { nsec3param; };",
        "reference": "https://tools.ietf.org/html/rfc5155"
    },
    36: {
        "fix": "Publish an SPF record with '-all' to hard-fail unauthorised senders.",
        "example": "v=spf1 include:_spf.example.com -all",
        "reference": "https://www.spf-record.com/"
    },
    37: {
        "fix": "Publish a DMARC record with p=quarantine or p=reject.",
        "example": "_dmarc.example.com. TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"",
        "reference": "https://dmarc.org/"
    },
    38: {
        "fix": "Publish DKIM records for your mail domains. Generate a key pair and add the public key as a TXT record.",
        "reference": "http://www.dkim.org/"
    },
    39: {
        "fix": "Add CAA records to restrict certificate issuance.",
        "example": "example.com. IN CAA 0 issue \"letsencrypt.org\"",
        "reference": "https://sslmate.com/caa/"
    },
    40: {
        "fix": "Disable zone transfers (AXFR) to unauthorized hosts. Use 'allow-transfer' directive.",
        "example": "options { allow-transfer { none; }; };",
        "reference": "https://www.zytrax.com/books/dns/ch7/xfer.html"
    },

    # Network Engine (301-305)
    301: {
        "fix": "List open ports – informational.",
        "reference": ""
    },
    302: {
        "fix": "Restrict management ports (22,80,443) to internal networks using firewall rules.",
        "example": "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT",
        "reference": "https://linux.die.net/man/8/iptables"
    },
    303: {
        "fix": "Do not expose login interfaces (HTTP/HTTPS) to the public internet. Use VPN or IP whitelisting.",
        "reference": "https://www.cisecurity.org/controls/"
    },
    304: {
        "fix": "List observed services – informational.",
        "reference": ""
    },
    305: {
        "fix": "Disable service banners that reveal version information. Configure services to hide version.",
        "example": "ServerTokens Prod (Apache) / server_tokens off; (Nginx)",
        "reference": "https://geekflare.com/important-http-headers/"
    },

    # SSH Engine (501-506)
    501: {
        "fix": "List open ports – informational.",
        "reference": ""
    },
    502: {
        "fix": "Hide SSH version banner. Set 'DebianBanner no' or 'VersionAddendum none' in sshd_config.",
        "example": "DebianBanner no",
        "reference": "https://www.ssh.com/academy/ssh/sshd_config"
    },
    503: {
        "fix": "Disable SSH protocol 1. Ensure 'Protocol 2' in sshd_config.",
        "example": "Protocol 2",
        "reference": "https://www.ssh.com/academy/ssh/protocol"
    },
    504: {
        "fix": "Use strong ciphers only. In sshd_config, set 'Ciphers' to a modern list.",
        "example": "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "reference": "https://stribika.github.io/2015/01/04/secure-secure-shell.html"
    },
    505: {
        "fix": "Use strong key exchange algorithms. Set 'KexAlgorithms' to a safe list.",
        "example": "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256",
        "reference": "https://www.ssh.com/academy/ssh/kex"
    },
    506: {
        "fix": "Use strong MAC algorithms. Set 'MACs' to a safe list.",
        "example": "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
        "reference": "https://www.ssh.com/academy/ssh/mac"
    },

    # FTP Engine (401-405)
    401: {
        "fix": "List open ports – informational.",
        "reference": ""
    },
    402: {
        "fix": "If FTP is not required, disable it. Otherwise ensure it's properly secured.",
        "reference": "https://www.ftpserver.org/security.html"
    },
    403: {
        "fix": "Hide FTP server version. In vsftpd, set 'ftpd_banner' to a generic banner.",
        "example": "ftpd_banner=Welcome to FTP service.",
        "reference": "https://security.appspot.com/vsftpd.html"
    },
    404: {
        "fix": "Use FTPS (FTP over SSL) or SFTP instead of plain FTP. Disable plain FTP if possible.",
        "example": "implicit_ssl=YES (vsftpd)",
        "reference": "https://www.ftpserver.org/security.html"
    },
    405: {
        "fix": "Disable anonymous FTP upload. Set 'anonymous_enable=NO' or restrict permissions.",
        "example": "anonymous_enable=NO (vsftpd)",
        "reference": "https://security.appspot.com/vsftpd.html"
    },

    # New Email Compliance (1001-1013)
    1001: {
        "fix": "Disable open relay by configuring the MTA to accept mail only for its own domains or from authenticated users.",
        "example": "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination",
        "reference": "https://www.postfix.org/SMTPD_ACCESS_README.html"
    },
    1002: {
        "fix": "Hide the MTA version string in the SMTP banner to prevent reconnaissance.",
        "example": "smtpd_banner = $myhostname ESMTP",
        "reference": "https://www.postfix.org/postconf.5.html#smtpd_banner"
    },
    1003: {
        "fix": "Ensure the MTA software is kept up-to-date with the latest security patches.",
        "reference": "https://www.cvedetails.com/"
    },
    1004: {
        "fix": "Enable and enforce STARTTLS support for all incoming and outgoing mail transfers.",
        "example": "smtpd_tls_security_level = may",
        "reference": "https://www.postfix.org/TLS_README.html"
    },
    1005: {
        "fix": "Disable SMTP authentication on the public MX interface or ensure it is only available over encrypted connections.",
        "example": "smtpd_sasl_auth_enable = no",
        "reference": "https://www.postfix.org/SASL_README.html"
    },
    1006: {
        "fix": "Disable the VRFY command to prevent attackers from discovering valid email addresses on your server.",
        "example": "disable_vrfy_command = yes",
        "reference": "https://www.postfix.org/postconf.5.html#disable_vrfy_command"
    },
    1007: {
        "fix": "Implement strict SPF, DKIM, and DMARC policies to prevent spoofing of your domain.",
        "reference": "https://www.agari.com/blog/dmarc-spoofing-protection"
    },
    1008: {
        "fix": "Enable IDN/Punycode filtering to detect and block homograph spoofing attacks.",
        "reference": "https://en.wikipedia.org/wiki/IDN_homograph_attack"
    },
    1009: {
        "fix": "Ensure that subdomains cannot be used to spoof the primary domain in email headers.",
        "reference": "https://dmarc.org/overview/"
    },
    1010: {
        "fix": "Extend Punycode filtering to subdomains to protect against complex homograph attacks.",
        "reference": "https://en.wikipedia.org/wiki/IDN_homograph_attack"
    },
    1011: {
        "fix": "Configure the mail server to reject unauthorized emails that claim to be from internal subdomains.",
        "reference": "https://dmarc.org/overview/"
    },
    1012: {
        "fix": "Use reputable RBL services to automatically reject mail from known spam sources and poor reputation IPs.",
        "example": "smtpd_client_restrictions = reject_rbl_client zen.spamhaus.org",
        "reference": "https://www.spamhaus.org/"
    },
    1013: {
        "fix": "Verify that your mail server's IP address has a valid PTR record that matches its hostname.",
        "reference": "https://www.spamresource.com/2013/01/why-reverse-dns-matters.html"
    },
    601: {
        "fix": "Disable PPTP protocol and close port 1723. Migrate to modern VPN protocols like IKEv2/IPsec or OpenVPN.",
        "reference": "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd334707(v=ws.10)"
    },
    602: {
        "fix": "Disable IKE Aggressive Mode on the VPN gateway. Use Main Mode instead, as Aggressive Mode is vulnerable to offline password cracking.",
        "reference": "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/14139-psk-aggressive-mode.html"
    },
    603: {
        "fix": "Update IKE/IPsec configuration to use strong algorithms (e.g., AES-GCM, SHA-256) and strong Diffie-Hellman groups (e.g., Group 14 or higher). Disable DES, 3DES, MD5, and SHA1.",
        "reference": "https://wiki.mozilla.org/Security/Guidelines/IPsec"
    },
    604: {
        "fix": "Complete removal of the PPTP service is recommended due to known security weaknesses in MS-CHAPv2 and MPPE.",
        "reference": "https://blog.cryptographyengineering.com/2012/08/16/attack-of-week-ms-chapv2/"
    },
    605: {
        "fix": "Apply strong TLS settings to the SSL VPN gateway. Disable TLS 1.0/1.1 and weak ciphers. Use modern AEAD-based cipher suites.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
    },
    606: {
        "fix": "Configure the VPN service to suppress version information in banners and handshake responses.",
        "reference": "https://www.sans.org/white-papers/110/"
    },
}
