# TIme_stampinf_document

To implement-:
• Creation of time stamping server
• Connection with client where the client will be using SHA256
• Transfer of file
• Creating digital signature
• Verification of digital signature
Assumption--
1.file does exist and its path is correct.
2.client and server exchange their public key.
3.There is a text file in the same folder with the given name.
4. file shouldn’t contain the hash value.
Modules Used:
1. import socket
2. import random
3. import time
4. import hashlib
5. from datetime import datetime.
