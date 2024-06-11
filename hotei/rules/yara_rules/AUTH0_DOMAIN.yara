rule AUTH0_DOMAIN {
    strings:
        $auth0_domain = /domain\s*:\s*gg-test\.auth0\.com/
    condition:
        $auth0_domain
}
