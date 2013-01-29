from clamav.client import ClamAV
from clamav.connection import (
    ConnectionPool,
    Connection,
    UnixDomainSocketConnection
)
from clamav.utils import from_url
from clamav.exceptions import (
    ConnectionError,
    DataError,
    InvalidResponse,
    ClamAVError,
    ResponseError,
)


__version__ = '2.7.2'
VERSION = tuple(map(int, __version__.split('.')))

__all__ = [
    'ClamAV', 'ConnectionPool',
    'Connection', 'UnixDomainSocketConnection',
    'ClamAVError', 'ConnectionError', 'ResponseError',
    'InvalidResponse', 'DataError', 'from_url',
]
