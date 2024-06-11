rule OAUTH_CONFIG {
    strings:
        $oauth_client_id = /ClientID\s*:\s*"[a-zA-Z0-9]{20,}/
        $oauth_client_secret = /ClientSecret\s*:\s*"[a-zA-Z0-9_]{40,}/
    condition:
        $oauth_client_id and $oauth_client_secret
}
