rule AWS_SECRET {
    strings:
        $aws_secret_key = /AWS_SECRET_ACCESS_KEY\s*=\s*[a-zA-Z0-9+=]{40}/
    condition:
        $aws_secret_key
}
