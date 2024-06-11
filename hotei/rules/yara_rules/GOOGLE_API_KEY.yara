rule Google_API_Key {
    strings:
        $api_key = /AIza[0-9A-Za-z_-]{35}/
    condition:
        $api_key
}
