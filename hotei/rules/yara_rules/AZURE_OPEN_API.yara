rule AZURE_OPEN_API {
    strings:
        $azure_open_api_url = /https?:\/\/([a-zA-Z0-9-]+\.)?azure-api\.net\b/
    condition:
        $azure_open_api_url
}
