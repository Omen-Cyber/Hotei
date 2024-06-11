rule DJANGO {
    strings:
        $django_creds = /DJANGO_[A-Z_]+=['"][^'"]+['"]/
    condition:
        $django_creds
}
