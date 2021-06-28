## Decision Trees
### Usage instructions

There is a utility that will streamline the process as much as possible. It can be run as follows:

```
cd <PROJECT_PATH>
python ./decision_trees/decision_tree_processor.py
```

Before running the utility, it is advised to tweak the following values, found in the top part of the file:

```python
ROOT_PATH = "./decision_trees/models/" # The base path where the AFM file can be found

FILE_NAME = "example" # The base file name

AFM_EXTENSION = ".afm" # example.afm - extension for the AFM file

AFM_JSON_EXTENSION = "-afm.json" # Where the JSON representation for the AFM file will be stored

AHP_EXTENSION = "-ahp.json" # Extension of the file that will store AHP tree and comparison data

DEMATEL_EXTENSION = "-dematel.json" # Extension of the file that will store DEMATEL tree and comparison data

AHP_WEIGHTS_EXTENSION = "-ahp-weights.json" # File that will store computed AHP weights

ALTERNATIVES_EXTENSION = "-alternatives.json" # TO BE MANUALLY CREATED BY USER. File with alternatives

RANK_OUTPUT_EXTENSION = "-rank-output.log" # Program output for alternative rankings

DEMATEL_OUTPUT_EXTENSION = "-dematel-output.log" # Program output for DEMATEL output data
```

The procedure to use the utility is outlined below:

1. Run the python file like shown above
2. If an AHP file doesn't exist yet, one is created with default weights
3. User is asked to customize the AHP comparison weights to their preferences
4. If a DEMATEL file doesn't exist yet, one is created with default weights. Note that the program is expected to fail if weights aren't changed from its defaults (they're all zero by default)
5. User is asked to customize the DEMATEL comparison weights to their preferences
6. If an alternatives file exists, alternatives are ranked using Weighted Sum, TOPSIS and VIKOR and stored in a separate file
7. If the DEMATEL file is correctly filled out, a 2D chart is displayed, and a file is created with output data from the algorithm


The alternatives file is a list of alternatives, each described by a list of features (individual nodes from the AHM tree).
An example alternative file is shown below:
```
[
    ["feature1", "feature2"],
    ["feature1", "feature3"],
    ["feature3", "feature4", "feature5"],
]
```
Note that since we're working with qualitative features, not including a feature in an alternative is equal to saying it has a value of 0.
E.g. the alternative matrix for the above file will be interpreted as follows:

| alternative | feature1 | feature2 | feature3 | feature4 | feature5 |
|-------------|----------|----------|----------|----------|----------|
| A0          | 1        | 1        | 0        | 0        | 0        |
| A1          | 1        | 0        | 1        | 0        | 0        |
| A2          | 0        | 0        | 1        | 1        | 1        |

### Usage example. CVE-2008-1678
The following is the AFM definition for CVE-2008-1678:
```
# vul_description: Memory leak in the zlib_stateful_init function in crypto/comp/c_zlib.c in libssl in OpenSSL 0.9.8f through 0.9.8h allows remote attackers to cause a denial of service (memory consumption) via multiple calls, as demonstrated by initial SSL client handshakes to the Apache HTTP Server mod_ssl that specify a compression algorithm.

%Relationships 
CVE_2008_1678: types sources exploits openssl;

types: application;
sources: nvd;

exploits: [direct] [indirect];
openssl: openssl_openssl;

openssl_openssl: openssl_openssl_version;

openssl_openssl_version: [1,1] {openssl_openssl_version_0__9__8g openssl_openssl_version_0__9__8f openssl_openssl_version_0__9__8h};



%Constraints 
openssl_openssl REQUIRES application;
```

After setting the `ROOT_PATH` and `FILE_NAME` values from the `decision_tree_processor.py` file and running it, these files will be generated:

CVE-2008-1678-afm.json
```json
{
    "CVE_2008_1678": {
        "types": "application",
        "sources": "nvd",
        "exploits": [
            "direct",
            "indirect"
        ],
        "openssl": {
            "openssl_openssl": {
                "openssl_openssl_version": [
                    "openssl_openssl_version_0__9__8g",
                    "openssl_openssl_version_0__9__8f",
                    "openssl_openssl_version_0__9__8h"
                ]
            }
        }
    }
}
```

CVE-2008-1678-ahp.json
Output will be similar to the following:
```json
{
    "py/object": "ahp_structure.AhpTree",
    "algorithm": "ahp",
    "version": 1,
    "nodes": {
        "children": [
            {
                "py/object": "ahp_structure.AhpNode",
                "id": "CVE_2008_1678",
                "children": [
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "types",
                        "children": [
                            {
                                "py/object": "ahp_structure.AhpNode",
                                "id": "application",
                                "children": [],
                                "comparisons": {}
                            }
                        ],
                        "comparisons": {}
                    },
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "sources",
                        "children": [
                            {
                                "py/object": "ahp_structure.AhpNode",
                                "id": "nvd",
                                "children": [],
                                "comparisons": {}
                            }
                        ],
                        "comparisons": {
                            "types": 1
                        }
                    },
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "exploits",
                        "children": [
                            {
                                "py/object": "ahp_structure.AhpNode",
                                "id": "direct",
                                "children": [],
                                "comparisons": {}
                            },
                            {
                                "py/object": "ahp_structure.AhpNode",
                                "id": "indirect",
                                "children": [],
                                "comparisons": {
                                    "direct": 1
                                }
                            }
                        ],
                        "comparisons": {
                            "types": 1,
                            "sources": 1
                        }
                    },
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "openssl",
                        "children": [
                            {
                                "py/object": "ahp_structure.AhpNode",
                                "id": "openssl_openssl",
                                "children": [
                                    {
                                        "py/object": "ahp_structure.AhpNode",
                                        "id": "openssl_openssl_version",
                                        "children": [
                                            {
                                                "py/object": "ahp_structure.AhpNode",
                                                "id": "openssl_openssl_version_0__9__8g",
                                                "children": [],
                                                "comparisons": {}
                                            },
                                            {
                                                "py/object": "ahp_structure.AhpNode",
                                                "id": "openssl_openssl_version_0__9__8f",
                                                "children": [],
                                                "comparisons": {
                                                    "openssl_openssl_version_0__9__8g": 1
                                                }
                                            },
                                            {
                                                "py/object": "ahp_structure.AhpNode",
                                                "id": "openssl_openssl_version_0__9__8h",
                                                "children": [],
                                                "comparisons": {
                                                    "openssl_openssl_version_0__9__8g": 1,
                                                    "openssl_openssl_version_0__9__8f": 1
                                                }
                                            }
                                        ],
                                        "comparisons": {}
                                    }
                                ],
                                "comparisons": {}
                            }
                        ],
                        "comparisons": {
                            "types": 1,
                            "sources": 1,
                            "exploits": 1
                        }
                    }
                ],
                "comparisons": {}
            }
        ]
    }
}
```

CVE-2008-1678-dematel.json
Output will be similar to the following:
```json
{
    "py/object": "ahp_structure.AhpTree",
    "algorithm": "ahp",
    "version": 1,
    "nodes": {
        "children": [
            {
                "py/object": "ahp_structure.AhpNode",
                "id": "types",
                "children": [
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "application",
                        "children": [],
                        "comparisons": {}
                    }
                ],
                "comparisons": {
                    "sources": 0,
                    "exploits": 1,
                    "openssl": 0
                }
            },
            {
                "py/object": "ahp_structure.AhpNode",
                "id": "sources",
                "children": [
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "nvd",
                        "children": [],
                        "comparisons": {}
                    }
                ],
                "comparisons": {
                    "types": 1,
                    "exploits": 1,
                    "openssl": 1
                }
            },
            {
                "py/object": "ahp_structure.AhpNode",
                "id": "exploits",
                "children": [
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "direct",
                        "children": [],
                        "comparisons": {
                            "indirect": 0
                        }
                    },
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "indirect",
                        "children": [],
                        "comparisons": {
                            "direct": 0
                        }
                    }
                ],
                "comparisons": {
                    "types": 0,
                    "sources": 1,
                    "openssl": 1
                }
            },
            {
                "py/object": "ahp_structure.AhpNode",
                "id": "openssl",
                "children": [
                    {
                        "py/object": "ahp_structure.AhpNode",
                        "id": "openssl_openssl",
                        "children": [
                            {
                                "py/object": "ahp_structure.AhpNode",
                                "id": "openssl_openssl_version",
                                "children": [
                                    {
                                        "py/object": "ahp_structure.AhpNode",
                                        "id": "openssl_openssl_version_0__9__8g",
                                        "children": [],
                                        "comparisons": {
                                            "openssl_openssl_version_0__9__8f": 0,
                                            "openssl_openssl_version_0__9__8h": 0
                                        }
                                    },
                                    {
                                        "py/object": "ahp_structure.AhpNode",
                                        "id": "openssl_openssl_version_0__9__8f",
                                        "children": [],
                                        "comparisons": {
                                            "openssl_openssl_version_0__9__8g": 3,
                                            "openssl_openssl_version_0__9__8h": 0
                                        }
                                    },
                                    {
                                        "py/object": "ahp_structure.AhpNode",
                                        "id": "openssl_openssl_version_0__9__8h",
                                        "children": [],
                                        "comparisons": {
                                            "openssl_openssl_version_0__9__8g": 0,
                                            "openssl_openssl_version_0__9__8f": 1
                                        }
                                    }
                                ],
                                "comparisons": {}
                            }
                        ],
                        "comparisons": {}
                    }
                ],
                "comparisons": {
                    "types": 0,
                    "sources": 0,
                    "exploits": 0
                }
            }
        ]
    }
}
```

The program will pause after generating the AHP JSON file, and also after generating the DEMATEL JSON file. The user will be prompted to tweak the weights. Once the user is happy with the weights, press RETURN/ENTER to continue generating the following files:


CVE-2008-1678-ahp-weights.json
Output for the weights set above:
```json
{
    "output_weights": {
        "application": 0.25,
        "nvd": 0.25,
        "indirect": 0.125,
        "direct": 0.125,
        "openssl_openssl_version_0__9__8h": 0.0833,
        "openssl_openssl_version_0__9__8g": 0.0833,
        "openssl_openssl_version_0__9__8f": 0.0833
    }
}
```

CVE-2008-1678-dematel-output.json
Output for the weights set above:
```json
{
    "quadrants": {
        "openssl_openssl_version_0__9__8g": 4,
        "sources": 2,
        "openssl": 2,
        "types": 2,
        "openssl_openssl_version_0__9__8f": 1,
        "exploits": 2,
        "openssl_openssl_version_0__9__8h": 1
    },
    "D_PLUS_R": [
        1.3333333333333333,
        0.0,
        0.0,
        0.0,
        1.3333333333333333,
        0.0,
        0.6666666666666666
    ],
    "D_MINUS_R": [
        -1.3333333333333333,
        0.0,
        0.0,
        0.0,
        0.6666666666666667,
        0.0,
        0.6666666666666666
    ],
    "WEIGHTS": [
        0.4,
        0.0,
        0.0,
        0.0,
        0.4,
        0.0,
        0.2
    ]
}
```

Lastly, if an alternatives file **created by the user** exists at the specified location (defined by `{ROOT_PATH}/CVE-2008-1678-alternatives.json`), the following file will be generated:

Alternatives file created by the user
CVE-2008-1678-alternatives.json
```json
[
    ["openssl_openssl_version_0__9__8g"],
    ["openssl_openssl_version_0__9__8h"]
]
```

CVE-2008-1678-rank-output.json
```json
{
    "ranks": {
        "wsm": {
            "RATE": {
                "A0": 0.0833,
                "A1": 0.0833
            },
            "RANK": {
                "A0": 1.0,
                "A1": 2.0
            }
        },
        "topsis": {
            "D+": {
                "A0": 0.0833,
                "A1": 0.0833
            },
            "D-": {
                "A0": 0.0833,
                "A1": 0.0833
            },
            "RATE": {
                "A0": 0.5,
                "A1": 0.5
            },
            "RANK": {
                "A0": 1.0,
                "A1": 2.0
            }
        },
        "vikor": {
            "S": {
                "A0": 0.0833,
                "A1": 0.0833
            },
            "P": {
                "A0": 0.0833,
                "A1": 0.0833
            },
            "RATE": {
                "A0": null,
                "A1": null
            },
            "RANK": {
                "A0": 1.0,
                "A1": 2.0
            }
        }
    }
}
```
