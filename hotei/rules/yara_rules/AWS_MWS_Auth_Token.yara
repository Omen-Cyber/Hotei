rule AWS_MWS_Auth_Token {
    strings:
        $aws_mws_auth_token = /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/
    condition:
        $aws_mws_auth_token
}
