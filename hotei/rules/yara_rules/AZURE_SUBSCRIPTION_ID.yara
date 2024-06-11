rule AZURE_SUBSCRIPTION_ID {
    strings:
        $azure_subscription_id = /\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b/
    condition:
        $azure_subscription_id
}
