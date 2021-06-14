JSON structure that represents an AFM tree
```json
{
    "CVE_2009_3555": {
        "types": [
            "operating_system", "application"
        ],
        "sources": "nvd",
        // "exploits": null,
        "exploits": {
            "direct":
            [
                "exploit_10579","exploit_10071"
            ],
            "indirect": {} // could be an empty object, list, or null
        },
        "apache": {
            "apache_http_server": {
                "apache_http_server_version":
                [
                    "apache_http_server_version_2_0_43",
                    "apache_http_server_version_2_0_65",
                    "apache_http_server_version_2_0_79",
                ]
            }
        },
        "openssl": {
            "openssl": {
                "openssl_openssl_version":
                [
                    "openssl_openssl_version_0_9_7g",
                    "openssl_openssl_version_0_9_6e",
                    "openssl_openssl_version_0_9_8f",
                ]
            }
        },
    }
}
```