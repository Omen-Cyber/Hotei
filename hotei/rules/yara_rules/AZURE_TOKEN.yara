rule AZURE_TOKEN {
    strings:
        $azure_token = /AZURE_TOKEN=[a-z0-9]{50,60}/
    condition:
        $azure_token
}
