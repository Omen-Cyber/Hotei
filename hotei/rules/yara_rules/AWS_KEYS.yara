rule AWS_Keys {
    strings:
        //$str_cid = /CLIENT_ID|CLIENT ID|username|awsaccesskeyid/i
        //$str_cs = /CLIENT_SECRET|CLIENT SECRET|password/i
        $client_id = /(AKIA|AIPA|ANPA|ASIA|ABIA)[A-Z0-9]{16}/
        $headers = /x-amz-signature|x-amz-algorithm|x-amz-credential/i
        //$client_secret = /[A-Za-z0-9\/+]{40}/
    condition:
        $client_id or $headers
}
