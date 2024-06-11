rule ARTIFACTORY_TOKEN {
    strings:
        $artifactory_token = /ARTIFACTORY_TOKEN\s*=\s*[A-Z0-9]{128}/
    condition:
        $artifactory_token
}
