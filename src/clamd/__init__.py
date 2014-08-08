#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

try:
    __version__ = __import__('pkg_resources').get_distribution('clamd').version
except:
    __version__ = ''

# $Source$


import socket
import sys
import struct
import contextlib
import re
import base64

scan_response = re.compile(r"^(?P<path>.*): ((?P<virus>.+) )?(?P<status>(FOUND|OK|ERROR))$")
EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E' \
                b'QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n')


class ClamdError(Exception):
    pass


class ResponseError(ClamdError):
    pass


class BufferTooLongError(ResponseError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""


class ConnectionError(ClamdError):
    """Class for errors communication with clamd"""


class ClamdNetworkSocket(object):
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
            e = sys.exc_info()[1]
            raise ConnectionError(self._error_message(e))

    def _error_message(self, exception):
        # args for socket.error can either be (errno, "message")
        # or just "message"
        if len(exception.args) == 1:
            return "Error connecting to {host}:{port}. {msg}.".format(
                host=self.host,
                port=self.port,
                msg=exception.args[0]
            )
        else:
            return "Error {erno} connecting {host}:{port}. {msg}.".format(
                erno=exception.args[0],
                host=self.host,
                port=self.port,
                msg=exception.args[1]
            )

    def ping(self):
        return self._basic_command("PING")

    def version(self):
        return self._basic_command("VERSION")

    def reload(self):
        return self._basic_command("RELOAD")

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
        finally:
            self._close_socket()

    def scan(self, file):
        return self._file_system_scan('SCAN', file)

    def contscan(self, file):
        return self._file_system_scan('CONTSCAN', file)

    def multiscan(self, file):
        return self._file_system_scan('MULTISCAN', file)

    def _basic_command(self, command):
        """
        Send a command to the clamav server, and return the reply.
        """
        self._init_socket()
        try:
            self._send_command(command)
            response = self._recv_response().rsplit("ERROR", 1)
            if len(response) > 1:
                raise ResponseError(response[0])
            else:
                return response[0]
        finally:
            self._close_socket()

    def _file_system_scan(self, command, file):
        """
        Scan a file or directory given by filename using multiple threads (faster on SMP machines).
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return:
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}

        May raise:
          - ConnectionError: in case of communication problem
        """

        try:
            self._init_socket()
            self._send_command(command, file)

            dr = {}
            for result in self._recv_response_multiline().split('\n'):
                if result:
                    filename, reason, status = self._parse_response(result)
                    dr[filename] = (status, reason)

            return dr

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
            self._send_command('INSTREAM')

            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf

            chunk = buff.read(max_chunk_size)
            while chunk:
                size = struct.pack(b'!L', len(chunk))
                self.clamd_socket.send(size + chunk)
                chunk = buff.read(max_chunk_size)

            self.clamd_socket.send(struct.pack(b'!L', 0))

            result = self._recv_response()

            if len(result) > 0:
                if result == 'INSTREAM size limit exceeded. ERROR':
                    raise BufferTooLongError(result)

                filename, reason, status = self._parse_response(result)
                return {filename: (status, reason)}
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
            self._send_command('STATS')
            return self._recv_response_multiline()
        finally:
            self._close_socket()

    def _send_command(self, cmd, *args):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        concat_args = ''
        if args:
            concat_args = ' ' + ' '.join(args)

        cmd = 'n{cmd}{args}\n'.format(cmd=cmd, args=concat_args).encode('utf-8')
        self.clamd_socket.send(cmd)

    def _recv_response(self):
        """
        receive line from clamd
        """
        try:
            with contextlib.closing(self.clamd_socket.makefile('rb')) as f:
                return f.readline().decode('utf-8').strip()
        except (socket.error, socket.timeout):
            e = sys.exc_info()[1]
            raise ConnectionError("Error while reading from socket: {0}".format(e.args))

    def _recv_response_multiline(self):
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        try:
            with contextlib.closing(self.clamd_socket.makefile('rb')) as f:
                return f.read().decode('utf-8')
        except (socket.error, socket.timeout):
            e = sys.exc_info()[1]
            raise ConnectionError("Error while reading from socket: {0}".format(e.args))

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
        try:
            return scan_response.match(msg).group("path", "virus", "status")
        except AttributeError:
            raise ResponseError(msg.rsplit("ERROR", 1)[0])


class ClamdUnixSocket(ClamdNetworkSocket):
    """
    Class for using clamd with an unix socket
    """
    def __init__(self, path="/var/run/clamav/clamd.ctl", timeout=None):
        """
        class initialisation

        path (string) : unix socket path
        timeout (float or None) : socket timeout
        """

        self.unix_socket = path
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
            e = sys.exc_info()[1]
            raise ConnectionError(self._error_message(e))

    def _error_message(self, exception):
        # args for socket.error can either be (errno, "message")
        # or just "message"
        if len(exception.args) == 1:
            return "Error connecting to {path}. {msg}.".format(
                path=self.unix_socket,
                msg=exception.args[0]
            )
        else:
            return "Error {erno} connecting {path}. {msg}.".format(
                erno=exception.args[0],
                path=self.unix_socket,
                msg=exception.args[1]
            )
