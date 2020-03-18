import clamd
import time

cd = clamd.ClamdNetworkSocket()
print(cd.version())
