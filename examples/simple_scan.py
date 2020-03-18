import clamd
import time

cd = clamd.ClamdNetworkSocket()
for i in range(3):
    print(cd.ping())
    time.sleep(1)
