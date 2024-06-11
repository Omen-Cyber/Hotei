rule SENSITIVE_DOCUMENTS {
strings:
        $keyword_string_1 = "asdfasdfasdfasdf" nocase
        $keyword_string_2 = "asdfasdfasdfasdf" nocase
        $keyword_string_3 = "asdfasdfasdfa" nocase
        $keyword_string_4 = "Customer" nocase
        //Sensitive data keywords
        $data_class_string_1 = "Secret" nocase
        $data_class_string_2 = "Restricted" nocase
        $data_class_string_3 = "Confidential" nocase
        $match_company_confidential = /Internal use only|Internal only|Do not distribute|Company confidential|Do not share externally|Internal Distributor Only|Internal Distribution Only/i

    condition:
        (1 of ($keyword*) and 1 of ($data*)) or $match_company_confidential
}
