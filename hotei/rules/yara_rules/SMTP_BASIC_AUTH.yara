rule SMTP_BASIC_AUTH {
    strings:
        $smtp_basic_auth = /Authorization\s*:\s*Basic\s*[a-zA-Z0-9=]{32}/
    condition:
        $smtp_basic_auth
}
