rule DOCKERHUB_TOKEN {
    strings:
        $dockerhub_token = /DOCKERHUB_TOKEN\s*:\s*"dckr_pat_[a-zA-Z0-9-]{64}"/
    condition:
        $dockerhub_token
}
