rule GOCARDLESS {
    strings:
        $gocardless_access_token = /'access_token'\s*:\s*'live_[a-zA-Z0-9-_]{30,}/
        $gocardless_webhook_secret = /'webhook_secret'\s*:\s*'YourSecretHere'/
    condition:
        $gocardless_access_token and $gocardless_webhook_secret
}
