rule MWS_AUTH_TOKEN {
    strings:
        $mws_auth_token = /\[MWSAuthToken\]\s*=>\s*[a-z0-9\-]{50,}/
    condition:
        $mws_auth_token
}
