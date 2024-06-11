rule BING_SUBSCRIPTION_KEY {
    strings:
        $bing_subscription_key = /Ocp-Apim-Subscription-Key\s*:\s*"[a-zA-Z0-9]{32}"/
    condition:
        $bing_subscription_key
}
