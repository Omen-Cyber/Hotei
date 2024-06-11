rule AWS_AppSync_GraphQL_Key {
    strings:
        $aws_appsync_graphql_key = /da2-[a-z0-9]{26}/
    condition:
        $aws_appsync_graphql_key
}
