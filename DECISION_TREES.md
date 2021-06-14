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
3. User is asked to customize the comparison weights to their preferences
4. If a DEMATEL file doesn't exist yet, one is created with default weights. Note that the program is expected to fail if weights aren't changed from its defaults (they're all zero by default)
5. User is asked to customize the comparison weights to their preferences
6. If an alternatives file is created, alternatives are ranked using Weighted Sum, TOPSIS and VIKOR
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
E.g. the alternative matrix for the above file will be processed as follows:

| alternative | feature1 | feature2 | feature3 | feature4 | feature5 |
|-------------|----------|----------|----------|----------|----------|
| A0          | 1        | 1        | 0        | 0        | 0        |
| A1          | 1        | 0        | 1        | 0        | 0        |
| A2          | 0        | 0        | 1        | 1        | 1        |
