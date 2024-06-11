rule SALESFORCE_DATA {
strings:
        $match_insider_threat = /apex account id|opportunity code|account id|account name/i
        $match_sf_export = /Report\sId:\s[0-9a-zA-Z]{17}/
        $match_sfdc_link = /.lightning\.force\.com[a-zA-Z0-9\/]{40,}view|app\.clari\.com\/.+/
condition:
        any of them
}
