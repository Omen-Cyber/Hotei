rule CONNECTION_URI {
    strings:
        $connection_uri = /connection_uri\s*=\s*"amqp:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+:[0-9]+\/[a-zA-Z0-9_]+"/
    condition:
        $connection_uri
}
