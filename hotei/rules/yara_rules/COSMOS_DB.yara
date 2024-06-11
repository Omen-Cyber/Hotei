rule COSMOS_DB {
    strings:
        $account_host = "host"
        $ACCOUNT_KEY = "master_key"
        $COSMOS_DATABASE = "database_id"
        $COSMOS_CONTAINER = "container_id"
        $cosmos_account_key = /[\'\"][a-zA-Z0-9+\/=]{88}[\'\"]/
    condition:
        all of them
}
