rule POST_PATTERN {
    strings:
        $post_pattern = /POST\s+https:\/\/ims-na1\.adobelogin\.com\/ims\/exchange\/jwt/
    condition:
        $post_pattern
}
