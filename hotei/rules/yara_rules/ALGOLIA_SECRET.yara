rule ALGOLIA_SECRET {
    strings:
        $algolia_client_id = /clientid\s*=\s*[A-Z0-9]{10}/
        $algolia_client_secret = /clientsecret\s*=\s*[a-zA-Z0-9]{32}/
    condition:
        $algolia_client_id and $algolia_client_secret
}
