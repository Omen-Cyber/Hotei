rule IO_SECRET {
    strings:
        $io_username = /IO_USERNAME\s*=\s*"[a-zA-Z0-9_]+"/
        $io_key = /IO_KEY\s*=\s*"aio_[a-zA-Z0-9]{32}"/
    condition:
        $io_username and $io_key
}
