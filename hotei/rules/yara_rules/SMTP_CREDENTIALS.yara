rule SMTP_CREDENTIALS {
    strings:
        $smtp_username = /Username\s*:\s*"[A-Z0-9]{20}"/
        $smtp_password = /Password\s*:\s*"[a-zA-Z0-9+\/=]{40}"/
    condition:
        $smtp_username and $smtp_password
}
