rule PRIVATE_KEY {
    strings:
        $private_key_begin = /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/
        $private_key_end = /-----END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/

    condition:
        all of them
}
