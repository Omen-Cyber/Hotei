rule ASANA_AUTHORIZATION {
    strings:
        $asana_authorization = /ASANA_AUTHORIZATION\s*=\s*'Bearer\s*[0-9\/:a-zA-Z]{50,}/
    condition:
        $asana_authorization
}
