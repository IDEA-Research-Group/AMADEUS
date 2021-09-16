import subprocess
import os
import time

file = open("models.txt", "r")

for line in file:
    model_name = line.strip("\n")
    if not os.path.isfile("fm/models/" + model_name + ".afm"):
        subprocess.Popen(["python", "main.py", "-k", model_name])
        time.sleep(7)
    else:
        print(line)
        continue
