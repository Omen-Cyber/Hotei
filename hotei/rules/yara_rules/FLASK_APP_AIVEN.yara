rule FLASK_APP_AIVEN {
    strings:
        $flask_app_aiven_api_key = /FLASK_APP_AIVEN_API_KEY\s*=\s*"[a-zA-Z0-9+\/=]{160,}"/
    condition:
        $flask_app_aiven_api_key
}
