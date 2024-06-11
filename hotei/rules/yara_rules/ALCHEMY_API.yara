rule ALCHEMY_API {
    strings:
        $alchemy_mainnet = /https:\/\/eth-mainnet\.alchemyapi\.io\/v2\/[a-zA-Z0-9_]{30,}/
    condition:
        $alchemy_mainnet
}
