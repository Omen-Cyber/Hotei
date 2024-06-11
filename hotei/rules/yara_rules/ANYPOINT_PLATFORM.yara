rule ANYPOINT_PLATFORM {
    strings:
        $client_id = /<anypoint\.platform\.client_id>\w+<\/anypoint\.platform\.client_id>/
        $client_secret = /<anypoint\.platform\.client_secret>\w+<\/anypoint\.platform\.client_secret>/
    condition:
        $client_id and $client_secret
}
