from afm_to_afm_json_converter import afm_to_afm_json_conversion
from afm_to_ahp_converter import afm_to_ahp_conversion
from ahp_processor import process_ahp
from topsis import rank_ahp_alternatives
from dematel import process_dematel
import os.path
import pathlib

'''
Procedimiento:
- Definir el modelo AFM con el modelo de características.
- Definir asimismo, opcionalmente un archivo de alternativas.
- Ejecutar una vez el decision_tree_processor para que genere los árboles de comparación
- Rellenamos los árboles de comparación (AHP, DEMATEL o ambos)
- Volvemos a ejecutar el decision_tree_processor para que rankee las alternativas en caso de estar definidas,
y muestre el gráfico DEMATEL
'''

ROOT_PATH = "./models/tfm/"
FILE_NAME = "tfm5"
AFM_EXTENSION = ".afm"
AFM_JSON_EXTENSION = "-afm.json"
AHP_EXTENSION = "-ahp.json"
DEMATEL_EXTENSION = "-dematel.json"
AHP_WEIGHTS_EXTENSION = "-ahp-weights.json"
ALTERNATIVES_EXTENSION = "-alternatives.json"
RANK_OUTPUT_EXTENSION = "-rank-output.json"
DEMATEL_OUTPUT_EXTENSION = "-dematel-output.json"

OUTPUT_PATH = ROOT_PATH + FILE_NAME + "/"
pathlib.Path(OUTPUT_PATH).mkdir(parents=True, exist_ok=True) 

afmFile = ROOT_PATH + FILE_NAME + AFM_EXTENSION
afmJsonFile = OUTPUT_PATH + FILE_NAME + AFM_JSON_EXTENSION
ahpFile = OUTPUT_PATH + FILE_NAME + AHP_EXTENSION
dematelFile = OUTPUT_PATH + FILE_NAME + DEMATEL_EXTENSION
ahpWeightsFile = OUTPUT_PATH + FILE_NAME + AHP_WEIGHTS_EXTENSION
alternativesFile = OUTPUT_PATH + FILE_NAME + ALTERNATIVES_EXTENSION
rankOutputFile = OUTPUT_PATH + FILE_NAME + RANK_OUTPUT_EXTENSION
dematelOutputFile = OUTPUT_PATH + FILE_NAME + DEMATEL_OUTPUT_EXTENSION

if not os.path.isfile(afmFile):
    print("FATAL: AFM file doesn't exist")
    exit()

if not os.path.isfile(afmJsonFile):
    afm_to_afm_json_conversion(afmFile, afmJsonFile)
else:
    print("AFM-JSON file already exists, omitting")

if not os.path.isfile(ahpFile):
    afm_to_ahp_conversion(afmJsonFile, ahpFile)
    input("AHP file created successfully. Please customize the weights to your liking and press any key to continue.")
else:
    input("AHP file already exists. Please double-check that the weights are correct press any key to continue.")

if not os.path.isfile(dematelFile):
    afm_to_ahp_conversion(afmJsonFile, dematelFile, True)
    input("DEMATEL file created successfully. Please customize the weights to your liking and press any key to continue.")
else:
    input("DEMATEL file already exists. Please double-check that the weights are correct press any key to continue.")

if not os.path.isfile(ahpWeightsFile):
    process_ahp(ahpFile, ahpWeightsFile)
else:
    print("AHP weights file already exists, omitting")

if os.path.isfile(alternativesFile):
    rank_ahp_alternatives(ahpWeightsFile, alternativesFile, rankOutputFile)
else:
    print("Can't do ranking without alternatives file. Create one (\"" + alternativesFile + "\") and rerun this program.")

if os.path.isfile(dematelFile):
    process_dematel(dematelFile, dematelOutputFile)
else:
    print("Can't do dematel processing without dematel file")