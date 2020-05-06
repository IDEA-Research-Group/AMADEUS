'''
    Mock data used to test functions related to
    Feature Model construction.
'''

from fm.structures import HashableCPE

def generate_mock_complex_CPEs():
    res = list()

    res.append(HashableCPE("cpe:2.3:a:adobe:flash_player_desktop_runtime:*:*:*:*:*:*:*:*"))
    res.append(HashableCPE("cpe:2.3:a:adobe:flash_player:*:*:*:*:*:chrome:*:*"))
    res.append(HashableCPE("cpe:2.3:a:adobe:flash_player:*:*:*:*:*:edge:*:*"))
    res.append(HashableCPE("cpe:2.3:a:apple:ios_11:*:*:*:*:*:*:*:*"))

    return res

def generate_mock_simple_CPEs(simple_cpe):
    mock = {
        "cpe:2.3:a:adobe:flash_player_desktop_runtime:*:*:*:*:*:*:*:*": 
            [HashableCPE("cpe:2.3:a:adobe:flash_player_desktop_runtime:30.0.0.154:*:*:*:*:*:*:*"), 
             HashableCPE("cpe:2.3:a:adobe:flash_player_desktop_runtime:32.0.0.171:*:*:*:*:*:*:*"), 
             HashableCPE("cpe:2.3:a:adobe:flash_player_desktop_runtime:18.0:*:*:*:*:*:*:*")],

        "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:chrome:*:*": 
            [HashableCPE("cpe:2.3:a:adobe:flash_player:18.0.0.204:*:*:*:*:chrome:*:*"), 
             HashableCPE("cpe:2.3:a:adobe:flash_player:32.0.0.192:*:*:*:*:chrome:*:*")],

        "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:edge:*:*": 
            [HashableCPE("cpe:2.3:a:adobe:flash_player:32.0.0.192:*:*:*:*:edge:*:*")],

        "cpe:2.3:a:apple:ios_11:*:*:*:*:*:*:*:*": [
            HashableCPE("cpe:2.3:a:apple:ios_11:*:canary3:*:*:*:*:*:*")]
    }

    return mock[simple_cpe]
