rule OKTA_OAUTH {

    strings:
        $clientId = /user\.oauth\.clientId=[\w-]+/
        $clientSecret = /user\.oauth\.clientSecret=[\w-]+/
    condition:
        all of ($clientId, $clientSecret)
}
