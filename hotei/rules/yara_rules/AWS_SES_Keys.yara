rule AWS_SES_Keys {
    strings:
        $username = /AKIA[0-9A-Z]{16}/
        $password = /[A-Za-z0-9]{43}==/
    condition:
        all of ($username, $password)
}
