rule detect_git_credentials {
    strings:
        $git_url_pattern = /git\+https:\/\/(?:[^:]+):[^@]+@[^\/]+\//
        $host_pattern = /host\s*:\s*[^ \r\n]+/
    condition:
        $git_url_pattern and $host_pattern
}
