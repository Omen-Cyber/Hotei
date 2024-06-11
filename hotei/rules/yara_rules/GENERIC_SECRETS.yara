rule GENERIC_SECRETS {

    strings:
            $match_env_vars_secrets =  /\b(hostname|dbuser|auth|id|user|login|api|guid|token)[=: ]{,3}[^\s'"]{8,120}/i
            $match_env_vars_accounts = /\b(apikey|secret|key|password|pass|pw)[=: ]{,3}[^\s'"]{8,120}/i
    condition:
            all of them
}
