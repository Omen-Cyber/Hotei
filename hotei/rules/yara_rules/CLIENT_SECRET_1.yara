rule CLIENT_SECRET_1 {
    strings:
        $client_id = /CLIENT_ID\s*=\s*[A-Z0-9]{20}/
        $client_secret = /CLIENT_SECRET\s*=\s*[a-zA-Z0-9]{40}/
    condition:
        $client_id and $client_secret
}
