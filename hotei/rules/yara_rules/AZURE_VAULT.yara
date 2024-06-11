rule AZURE_VAULT {

    strings:
            $match_azure_vault = /\\.vault\\.azure\\.net/
    condition:
            $match_azure_vault
}
