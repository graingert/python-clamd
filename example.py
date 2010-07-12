#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pyclamd

cd = pyclamd.clamd_unix_socket()
print(cd.ping())
print(cd.version())
print(cd.reload())
print(cd.stats())
print(cd.scan_stream(cd.EICAR()))
open('/tmp/EICAR','w').write(cd.EICAR())
print(cd.scan_file('/tmp/EICAR'))
