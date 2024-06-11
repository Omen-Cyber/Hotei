rule GITLAB_TOKEN {
    strings:
        $gitlab_token = /gitlab\+deploy-token-[0-9]{1,3}:[a-zA-Z0-9-_]{20}/
    condition:
        $gitlab_token
}
