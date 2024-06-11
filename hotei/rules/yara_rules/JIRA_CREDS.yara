rule JIRA_CREDS {
    strings:
        $jira_user = /jiraUser\s*:\s*'[a-zA-Z0-9@._-]+',/i
        $jira_password = /jiraPassword\s*:\s*'[a-zA-Z0-9@._-]+',/i
    condition:
        $jira_user and $jira_password
}
