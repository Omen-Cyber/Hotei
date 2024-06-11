rule BARD_API_KEY {
    strings:
        $bard_api_key = /new Bard\("[a-zA-Z0-9._-]{40,}\)/
    condition:
        $bard_api_key
}
