rule GITHUB_CLIENT {
    strings:
        $github_client_id = /Client ID\s*=\s*[a-f0-9]{20}/
        $github_client_secret = /Client secret\s*=\s*[a-f0-9]{40}/
    condition:
        $github_client_id and $github_client_secret
}
