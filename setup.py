
from distutils.core import setup

# Install : python setup.py install
# Register : python setup.py register

#  platform = 'Unix',
#  download_url = 'http://xael.org/norman/python/pyclamd/',


setup (name = 'clamd',
       version = "0.3.0",

       package_dir={'clamd': ''},
       packages=['clamd'],

       author = 'Alexandre Norman',
       author_email = 'norman@xael.org',
       license ='LGPL',
       keywords="python, clamav, antivirus, scanner, virus, libclamav".split(", "),
       url = 'https://github.com/graingert/python-clamd/',
       description = 'Clamd is a python interface to Clamd (Clamav daemon).',
       long_description = 'Clamd is a python interface to Clamd (Clamav daemon). By using Clamd, you can add virus detection capabilities to your python software in an efficient and easy way. Instead of PyClamav which uses libclamav, clamd may be used by a closed source product.')
