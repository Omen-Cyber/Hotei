rule GITHUB_TOKEN {
    strings:
        $github_token = /github_token\s*:\s*[a-f0-9]{40}/
    condition:
        $github_token
}
