rule GOOGLE_CLIENT_SECRET {
    strings:
        $google_client_secret = /\{\[^\{\]+auth_provider_x509_cert_url\[^\}\]+\}/
    condition:
        $google_client_secret
}
