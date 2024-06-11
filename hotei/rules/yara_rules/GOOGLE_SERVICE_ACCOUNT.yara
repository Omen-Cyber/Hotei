rule GOOGLE_SERVICE_ACCOUNT {
    strings:
        $sa_service_account = /"type":[^,]+/
        $sa_project_id = /"project_id":[^,]+/
        $sa_private_key_id = /"private_key_id":[^,]+/

        $sk_client_email = /client_email[:=].+/
        $sk_project_id = /project_id[:=].+/
        $sk_private_key = /private_key[:=].+/

    condition:

        all of ($sa*) or all of ($sk*)
}