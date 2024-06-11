rule BASIC_AUTH {
    strings:
        $basic_auth = /Authorization\s*:\s*Basic\s*[a-zA-Z0-9+\/=]{20,}/
    condition:
        $basic_auth
}
