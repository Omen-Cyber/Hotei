rule AZURE_OPENAI {
    strings:
        $azure_openai_endpoint = /AZURE_OPENAI_ENDPOINT\s*:\s*"https:\/\/my-gpt\.openai\.azure\.com\/openai\/deployments\/my-deployment"/
        $azure_openai_apikey = /AZURE_OPENAI_APIKEY\s*:\s*"[a-zA-Z0-9]{32}"/
    condition:
        $azure_openai_endpoint and $azure_openai_apikey
}
