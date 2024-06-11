rule ELASTIC_CLOUD {
    strings:
        $elastic_cloud_creds = /[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@cloud\.elastic\.co\b/
    condition:
        $elastic_cloud_creds
}
