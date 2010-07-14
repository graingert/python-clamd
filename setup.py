
from distutils.core import setup, Extension

pyclamd = Extension('pyclamd',
                    sources = ['pyclamd.py'])

# Install : python setup.py install
# Register : python setup.py register

#  platform = 'Unix',
#  download_url = 'http://xael.org/norman/python/pyclamd/',

import pyclamd

setup (name = 'pyClamd',
       version = pyclamd.__version__,

       package_dir={'pyclamd': ''},
       packages=['pyclamd'],

       author = 'Alexandre Norman',
       author_email = 'norman()xael.org',
       license ='LGPL',
       keywords="python, clamav, antivirus, scanner, virus, libclamav",
       url = 'http://xael.org/norman/python/pyclamd/',
       include_dirs = ['/usr/local/include'],
       description = 'pyClamd is a python interface to Clamd (Clamav daemon).',
       long_description = 'pyClamd is a python interface to Clamd (Clamav daemon). By using pyClamd, you can add virus detection capabilities to your python software in an efficient and easy way. Instead of pyClamav which uses libclamav, pyClamd may be used by a closed source product.')
