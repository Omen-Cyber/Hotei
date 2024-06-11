rule ACCESS_KEYS {
    strings:
        $access_key_id = /\$accessKeyId\s*=\s*"[A-Z0-9]{20}"/
        $access_key_secret = /\$accessKeySecret\s*=\s*"[a-zA-Z0-9+\/=]{40}"/
    condition:
        $access_key_id and $access_key_secret
}
