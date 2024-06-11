rule SPLUNK_LOGIN {
    strings:
        $user_info_section = /^\[user_info\]\s*$/
        $username = /USERNAME\s*=\s*\w+/
        $password = /PASSWORD\s*=\s*\w+/

    condition:
        all of them
}
