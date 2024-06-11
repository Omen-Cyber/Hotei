rule GITGUARDIAN_API {
    strings:
        $gitguardian_api = /Authorization\s*:\s*Token\s*[a-zA-Z0-9]{40}/
    condition:
        $gitguardian_api
}
