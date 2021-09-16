import subprocess
import time
import os

file = open("models.txt", "r")

i = 0
for line in file:
    path = line.strip("\n")
    if os.path.isfile("fm/models/" + path + ".afm"):
        subprocess.Popen(["python", "main.py", "-pn", "fm/models/" + path + ".afm"])
        time.sleep(7)
    else:
        print(line)
        continue
