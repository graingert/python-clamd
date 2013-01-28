#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
>>> cd = clamd.ClamdUnixSocket()
>>> cd.ping()
True
>>> cd.version().split()[0]
'ClamAV'
>>> cd.reload()
'RELOADING'
>>> open('/tmp/EICAR','w').write(cd.EICAR())
>>> cd.scan_file('/tmp/EICAR')
{'/tmp/EICAR': ('FOUND', 'Eicar-Test-Signature')}
>>> cd.scan_stream(cd.EICAR())
{'stream': ('FOUND', 'Eicar-Test-Signature')}

"""

try:
    __version__ = __import__('pkg_resources').get_distribution('d2to1').version
except:
    __version__ = ''

# $Source$


import socket
import types
import struct
import string
from StringIO import StringIO


class BufferTooLongError(ValueError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""


class ConnectionError(socket.error):
    """Class for errors communication with clamd"""


class _ClamdGeneric(object):
    """
    Abstract class for clamd
    """

    def EICAR(self):
        """
        returns Eicar test string
        """
        # Eicar test string (encoded for skipping virus scanners)
        EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E' \
                'QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n'.decode('base64')
        return EICAR

    def ping(self):
        """
        Send a PING to the clamav server, which should reply
        by a PONG.

        return: True if the server replies to PING

        May raise:
          - ConnectionError: if the server do not reply by PONG
        """

        self._init_socket()

        try:
            self._send_command('PING')
            result = self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could not ping clamd server')

        if result == 'PONG':
            return True
        else:
            raise ConnectionError('Could not ping clamd server')
        return

    def version(self):
        """
        Get Clamscan version

        return: (string) clamscan version

        May raise:
          - ConnectionError: in case of communication problem
        """
        self._init_socket()
        try:
            self._send_command('VERSION')
            result = self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could not get version information from server')

        return result

    def stats(self):
        """
        Get Clamscan stats

        return: (string) clamscan stats

        May raise:
          - ConnectionError: in case of communication problem
        """
        self._init_socket()
        try:
            self._send_command('STATS')
            result = self._recv_response_multiline()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could not get version information from server')

        return result

    def reload(self):
        """
        Force Clamd to reload signature database

        return: (string) "RELOADING"

        May raise:
          - ConnectionError: in case of communication problem
        """

        try:
            self._init_socket()
            self._send_command('RELOAD')
            result = self._recv_response()
            self._close_socket()

        except socket.error:
            raise ConnectionError('Could probably not reload signature database')

        return result

    def shutdown(self):
        """
        Force Clamd to shutdown and exit

        return: nothing

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command('SHUTDOWN')
            # result = self._recv_response()
            self._close_socket()
        except socket.error:
            raise ConnectionError('Could probably not shutdown clamd')

    def scan_file(self, file):
        """
        Scan a file or directory given by filename and stop on first virus or error found.
        Scan with archive support enabled.

        file (string) : filename or directory (MUST BE ABSOLUTE PATH !)

        return either :
          - (dict): {filename1: "virusname"}
          - None: if no virus found

        May raise :
          - ConnectionError: in case of communication problem
          - socket.timeout: if timeout has expired
        """

        try:
            self._init_socket()
            self._send_command('SCAN %s' % file)
        except socket.error:
            raise ConnectionError('Unable to scan %s' % file)

        result = '...'
        dr = {}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan %s' % file)

            if len(result) > 0:
                filename, reason, status = self._parse_response(result)

                if status == 'ERROR':
                    dr[filename] = ('ERROR', '{0}'.format(reason))
                    return dr

                elif status == 'FOUND':
                    dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr

    def multiscan_file(self, file):
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
            self._send_command('MULTISCAN %s' % file)
        except socket.error:
            raise ConnectionError('Unable to scan %s' % file)

        result = '...'
        dr = {}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan %s' % file)

            if len(result) > 0:
                filename, reason, status = self._parse_response(result)

                if status == 'ERROR':
                    dr[filename] = ('ERROR', '{0}'.format(reason))

                elif status == 'FOUND':
                    dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr

    def contscan_file(self, file):
        """
        Scan a file or directory given by filename
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
            self._send_command('CONTSCAN %s' % file)
        except socket.error:
            raise ConnectionError('Unable to scan %s' % file)

        result = '...'
        dr = {}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan %s' % file)

            if len(result) > 0:
                filename, reason, status = self._parse_response(result)

                if status == 'ERROR':
                    dr[filename] = ('ERROR', '{0}'.format(reason))

                elif status == 'FOUND':
                    dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr

    def scan_stream(self, buffer):
        """
        Scan a buffer

        buffer (string or filelikeobj): buffer to scan

        return either:
          - (dict): {filename1: "virusname"}
          - None: if no virus found

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """

        if hasattr(buffer, 'read'):
            infile = buffer
        else:
            infile = StringIO(buffer)

        try:
            self._init_socket()
            self._send_command('INSTREAM')

            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf

            chunk = infile.read(max_chunk_size)
            while chunk:
                size = struct.pack('!L', len(chunk))
                self.clamd_socket.send('{0}{1}'.format(size, chunk))
                chunk = infile.read(max_chunk_size)

            self.clamd_socket.send(struct.pack('!L', 0))

        except socket.error:
            raise ConnectionError('Unable to scan stream')

        result = '...'
        dr = {}
        while result:
            try:
                result = self._recv_response()
            except socket.error:
                raise ConnectionError('Unable to scan stream')

            if len(result) > 0:

                if result == 'INSTREAM size limit exceeded. ERROR':
                    raise BufferTooLongError(result)

                filename, reason, status = self._parse_response(result)

                if status == 'ERROR':
                    dr[filename] = ('ERROR', '{0}'.format(reason))

                elif status == 'FOUND':
                    dr[filename] = ('FOUND', '{0}'.format(reason))

        self._close_socket()
        if not dr:
            return None
        return dr

    def _send_command(self, cmd):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """

        cmd = 'n%s\n' % cmd
        self.clamd_socket.send(cmd)
        return

    def _recv_response(self):
        """
        receive response from clamd and strip all whitespace characters
        """
        response = self.clamd_socket.recv(4096).strip()
        return response

    def _recv_response_multiline(self):
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        response = ''
        c = '...'
        while c != '':
            try:
                c = self.clamd_socket.recv(4096).strip()
            except socket.error:
                break
            response += '{0}\n'.format(c)
        return response

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

        msg = msg.strip()
        filename = msg.split(': ')[0]
        left = msg.split(': ')[1:]
        if type(left) in types.StringTypes:
            result = left
        else:
            result = string.join(left, ': ')

        if result != 'OK':
            parts = result.split()
            reason = ' '.join(parts[:-1])
            status = parts[-1]
        else:
            reason, status = '', 'OK'

        return filename, reason, status


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
            raise ConnectionError('Could not reach clamd using unix socket (%s)' %
                        (self.unix_socket))


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
            raise ConnectionError('Could not reach clamd using network (%s, %s)' %
                        (self.host, self.port))

        return
