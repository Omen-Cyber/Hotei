rule AKAMAI_TOKEN {
    strings:
        $akamai_access_token = /access-token\s*=\s*[a-zA-Z0-9\-]{50,}/
        $akamai_client_token = /client-token\s*=\s*[a-zA-Z0-9\-]{50,}/
        $akamai_client_secret = /client-secret\s*=\s*[a-zA-Z0-9+\/=]{30,}/
    condition:
        $akamai_access_token or $akamai_client_token or $akamai_client_secret
}
