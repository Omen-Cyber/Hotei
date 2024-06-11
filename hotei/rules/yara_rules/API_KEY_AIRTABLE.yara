rule API_KEY_AIRTABLE {
    strings:
        $api_key_airtable = /apiKey\s*:\s*"key[a-zA-Z0-9]{14}"/
    condition:
        $api_key_airtable
}
