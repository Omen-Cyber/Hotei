rule AZURE_AD {
    strings:
        $azure_ad_client_id = /spring\.cloud\.azure\.active-directory\.credential\.client-id\s*=\s*[a-z0-9-]{36}/
        $azure_ad_client_secret = /spring\.cloud\.azure\.active-directory\.credential\.client-secret\s*=\s*[a-zA-Z0-9_~]{40}/
    condition:
        $azure_ad_client_id and $azure_ad_client_secret
}
