rule detect_jwt_token {
    strings:
        $jwt_pattern = /[A-Za-z0-9_=]{20,}\.[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_+=]{20,}/
    condition:
        $jwt_pattern
}
