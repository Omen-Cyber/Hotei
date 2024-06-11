rule BASE64_ENCODED_CLIENT_SECRET {
    strings:
        $client_id_base64 = /client id\s*=\s*[A-Za-z0-9=+]{28}/
        $client_secret_base64 = /CLIENT SECRET\s*=\s*[A-Za-z0-9=+]{40}/
    condition:
        $client_id_base64 and $client_secret_base64
}
