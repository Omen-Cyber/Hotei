rule AGORA_APP {
    strings:
        $agora_app_id = /AGORA_APP_ID\s*=\s*[a-zA-Z0-9]{32}/
        $agora_app_certificate = /AGORA_APP_CERTIFICATE\s*=\s*[a-zA-Z0-9]{40}/
    condition:
        $agora_app_id and $agora_app_certificate
}
