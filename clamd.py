#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
"""
clamd.py

Author : Alexandre Norman - norman()xael.org
Contributors :
  Philippe Lagadec - philippe.lagadec()laposte.net
  Thomas Kastner - tk()underground8.com
Licence : LGPL

Usage :

Test strings :
^^^^^^^^^^^^

>>> import clamd
>>> from six import BytesIO
>>> cd = clamd.ClamdUnixSocket()
>>> cd.ping()
True
>>> cd.version().split()[0]
'ClamAV'
>>> cd.reload()
'RELOADING'
>>> open('/tmp/EICAR','w').write(clamd.EICAR)
>>> cd.scan('/tmp/EICAR')
{'/tmp/EICAR': ('FOUND', 'Eicar-Test-Signature')}
>>> cd.instream(BytesIO(clamd.EICAR))
{'stream': ('FOUND', 'Eicar-Test-Signature')}

"""

try:
    __version__ = __import__('pkg_resources').get_distribution('clamd').version
except:
    __version__ = ''

# $Source$


import socket
import struct
import contextlib
import re
import base64

scan_response = re.compile(r"^(?P<path>.*): ((?P<virus>.+) )?(?P<status>(FOUND|OK|ERROR))$")
EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E' \
                b'QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n')


class BufferTooLongError(ValueError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""


class ConnectionError(socket.error):
    """Class for errors communication with clamd"""


class _ClamdGeneric(object):
    """
    Abstract class for clamd
    """

    def ping(self):
        return self._basic_command(b"PING")

    def version(self):
        return self._basic_command(b"VERSION")

    def reload(self):
        return self._basic_command(b"RELOAD")

    def shutdown(self):
        """
        Force Clamd to shutdown and exit

        return: nothing

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command(b'SHUTDOWN')
            # result = self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could probably not shutdown clamd')

    def scan(self, file):
        return self._file_system_scan(b'SCAN', file)

    def contscan(self, file):
        return self._file_system_scan(b'CONTSCAN', file)

    def multiscan(self, file):
        return self._file_system_scan(b'MULTISCAN', file)

    def _basic_command(self, command):
        """
        Send a command to the clamav server, and return the reply.
        """
        self._init_socket()
        try:
            self._send_command(command)
            return self._recv_response()
        except socket.error:
            raise ConnectionError('Could not complete command {command}'.format(command=command))
        finally:
            self._close_socket()

    def _file_system_scan(self, command, file):
        """
        Scan a file or directory given by filename using multiple threads (faster on SMP machines).
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return either :
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}
          - None: if no virus found

        May raise:
          - ConnectionError: in case of communication problem
        """

        try:
            self._init_socket()
            self._send_command(b'{command} {arg}'.format(
                command=command,
                arg=file
            ))

            dr = {}
            for result in self._recv_response_multiline().split('\n'):
                if result:
                    filename, reason, status = self._parse_response(result)
                    dr[filename] = (status, reason)

            if not dr:
                return None
            return dr

        except socket.error:
            raise ConnectionError('Unable to scan {file}'.format(file=file))
        finally:
            self._close_socket()

    def instream(self, buff):
        """
        Scan a buffer

        buff  filelikeobj: buffer to scan

        return:
          - (dict): {filename1: ("virusname", "status")}

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """

        try:
            self._init_socket()
            self._send_command(b'INSTREAM')

            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf

            chunk = buff.read(max_chunk_size)
            while chunk:
                size = struct.pack(b'!L', len(chunk))
                self.clamd_socket.send('{0}{1}'.format(size, chunk))
                chunk = buff.read(max_chunk_size)

            self.clamd_socket.send(struct.pack(b'!L', 0))

            result = self._recv_response()

            if len(result) > 0:
                if result == 'INSTREAM size limit exceeded. ERROR':
                    raise BufferTooLongError(result)

                filename, reason, status = self._parse_response(result)
                return {filename: (status, reason)}

        except socket.error:
            raise ConnectionError('Unable to scan stream')
        finally:
            self._close_socket()

    def stats(self):
        """
        Get Clamscan stats

        return: (string) clamscan stats

        May raise:
          - ConnectionError: in case of communication problem
        """
        self._init_socket()
        try:
            self._send_command(b'STATS')
            return self._recv_response_multiline()
        except socket.error:
            raise ConnectionError('Could not get version information from server')
        finally:
            self._close_socket()

    def _send_command(self, cmd):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """

        cmd = b'n{0}\n'.format(cmd)
        self.clamd_socket.send(cmd)
        return

    def _recv_response(self):
        """
        receive line from clamd
        """
        with contextlib.closing(self.clamd_socket.makefile('r+w')) as f:
            return f.readline().strip()

    def _recv_response_multiline(self):
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        with contextlib.closing(self.clamd_socket.makefile('r+w')) as f:
            return f.read()

    def _close_socket(self):
        """
        close clamd socket
        """
        self.clamd_socket.close()
        return

    def _parse_response(self, msg):
        """
        parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
        """
        return scan_response.match(msg).group("path", "virus", "status")


class ClamdUnixSocket(_ClamdGeneric):
    """
    Class for using clamd with an unix socket
    """
    def __init__(self, filename="/var/run/clamav/clamd.ctl", timeout=None):
        """
        class initialisation

        filename (string) : unix socket filename
        timeout (float or None) : socket timeout
        """

        self.unix_socket = filename
        self.timeout = timeout

    def _init_socket(self):
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.clamd_socket.connect(self.unix_socket)
            self.clamd_socket.settimeout(self.timeout)
        except socket.error:
            raise ConnectionError('Could not reach clamd using unix socket {0}'.format(self.unix_socket))


class ClamdNetworkSocket(_ClamdGeneric):
    """
    Class for using clamd with a network socket
    """
    def __init__(self, host='127.0.0.1', port=3310, timeout=None):
        """
        class initialisation

        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : socket timeout
        """

        self.host = host
        self.port = port
        self.timeout = timeout

    def _init_socket(self):
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.clamd_socket.connect((self.host, self.port))
            self.clamd_socket.settimeout(self.timeout)

        except socket.error:
            raise ConnectionError('Could not reach clamd using network ({host}, {port})'.format(
                    host=self.host,
                    port=self.port
                )
            )
