Usage
*****


Initializing the connection
===========================

``python-clamd`` communicates with ``clamd`` via sockets, in particular ``clamd`` which listens on a UNIX socket, and/or a network socket. 

UNIX socket connections
-----------------------

To use with a unix socket:

.. code-block:: python

        >>> import clamd
        >>> cd = clamd.ClamdUnixSocket()



Network socket connections
--------------------------

To initialize a connect with a socket over the network:

.. code-block:: python

        >>> import clamd
        >>> cd = clamd.ClamdNetworkSocket()


Verify the connection is working:

.. code-block:: python

        >>> cd.ping()
        'PONG'
        >>> cd.version()
        'ClamAV ...'
        >>> cd.reload()
        'RELOADING'


Scanning 
========

``python-clamd`` accepts **two ways** to provide input to a scan: either as a *file*, or a *stream*. 


File scanning
-------------

To scan a file:

.. code-block:: python

        >>> open('/tmp/EICAR','wb').write(clamd.EICAR)
        >>> cd.scan('/tmp/EICAR')
        {'/tmp/EICAR': ('FOUND', 'Eicar-Test-Signature')}


Stream scanning
---------------

.. code-block:: python

        >>> from io import BytesIO
        >>> cd.instream(BytesIO(clamd.EICAR))
        {'stream': ('FOUND', 'Eicar-Test-Signature')}

