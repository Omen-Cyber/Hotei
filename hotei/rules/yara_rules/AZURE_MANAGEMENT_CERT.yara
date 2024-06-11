rule AZURE_MANAGEMENT_CERT {
    strings:
        $azure_management_cert = /ManagementCertificate=[a-zA-Z0-9,.\/=+-]+/
    condition:
        $azure_management_cert
}
