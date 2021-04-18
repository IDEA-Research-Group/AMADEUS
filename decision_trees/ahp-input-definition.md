```json
// AHP input definition
{
    "algorithm": "ahp",
    "version": 1,
    "nodes": {
        "children": [
            // nodes at the root
            {
                "id": "apache",
                "children": [
                    {
                        "id": "apache-http_server-version",
                        "children": [
                            {
                                "id": "apache_http_server-version-2_0_0",
                                "comparisons": {
                                    // comparisons with siblings
                                    "apache-http_server-version_2_1_0": 0.5,
                                    "apache-http_server-version_2_2_0": 0.25,
                                }
                            },
                            {
                                "id": "apache_http_server-version-2_1_0",
                                "comparisons": {
                                    "apache-http_server-version_2_2_0": 0.5,
                                }
                            },
                            {
                                "id": "apache_http_server-version-2_2_0",
                            }
                        ]
                    }
                ],
                "comparisons": 
                {
                    "openssl": 2
                }
            },
            {
                "id": "openssl",
                "children": [
                    {
                        "id": "openssl-openssl-version",
                        "children": [
                            {
                                "id": "openssl-openssl-version-0_9_4",
                                "comparisons": {
                                    // comparisons with siblings
                                    "openssl-openssl-version-0_9_7b": 0.5,
                                    "openssl-openssl-version-0_9_8": 0.25,
                                }
                            },
                            {
                                "id": "openssl-openssl-version-0_9_7b",
                                "comparisons": {
                                    "apache-http_server-version_2_2_0": 0.5,
                                }
                            },
                            {
                                "id": "openssl-openssl-version-0_9_8",
                            }
                        ]
                    }
                ]
            }
        ]
    }
}
```