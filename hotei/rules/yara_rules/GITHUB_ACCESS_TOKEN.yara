rule GITHUB_ACCESS_TOKEN {
    strings:
        $github_access_token = /githubAccessToken\s*=\s*"[a-f0-9]{40}"/
    condition:
        $github_access_token
}
