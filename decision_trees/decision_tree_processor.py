from afm_to_ahp_converter import afm_to_ahp_conversion
from ahp_processor import process_ahp
from topsis import rank_ahp_alternatives
from dematel import process_dematel
import os.path

'''
Procedimiento:
- Definir el archivo AFM JSON con el modelo de características.
- Definir asimismo, opcionalmente un archivo de alternativas.
- Ejecutar una vez el decision_tree_processor para que genere los árboles de comparación
- Rellenamos los árboles de comparación (AHP, DEMATEL o ambos)
- Volvemos a ejecutar el decision_tree_processor para que rankee las alternativas en caso de estar definidas,
y muestre el gráfico DEMATEL
'''

ROOT_PATH = "./decision_trees/json_afm_models/tfm/"

AFM_FILE = ROOT_PATH + "tfm1-afm.json"
AHP_FILE = ROOT_PATH + "tfm1-compare-ahp.json"
DEMATEL_FILE = ROOT_PATH + "tfm1-compare-dematel.json"
AHP_WEIGHTS = ROOT_PATH + "tfm1-ahp-weights.json"
ALTERNATIVES = ROOT_PATH + "tfm1-ahp-alternatives.json"

if not os.path.isfile(AHP_FILE):
    afm_to_ahp_conversion(AFM_FILE, AHP_FILE)
else:
    print("AHP file already exists, omitting")

if not os.path.isfile(DEMATEL_FILE):
    afm_to_ahp_conversion(AFM_FILE, DEMATEL_FILE, True)
else:
    print("DEMATEL file already exists, omitting")

if not os.path.isfile(AHP_WEIGHTS):
    process_ahp(AHP_FILE, AHP_WEIGHTS)
else:
    print("AHP weights file already exists, omitting")

if os.path.isfile(ALTERNATIVES):
    rank_ahp_alternatives(AHP_WEIGHTS, ALTERNATIVES)
else:
    print("Can't do ranking without alternatives file")

if os.path.isfile(DEMATEL_FILE):
    process_dematel(DEMATEL_FILE)
else:
    print("Can't do dematel processing without dematel file")