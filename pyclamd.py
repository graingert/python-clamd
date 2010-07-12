#!/usr/bin/env python
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------
# LICENSE:
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free 
# Software  Foundation; either version 3 of the License, or (at your option) any
# later version. See http://www.gnu.org/licenses/lgpl-3.0.txt.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more 
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 675 Mass Ave, Cambridge, MA 02139, USA.
#------------------------------------------------------------------------------
# CHANGELOG:
# 2006-07-15 v0.1.1 AN: - released version
# 2007-10-09 v0.2.0 PL: - fixed error with deprecated string exceptions
#					    - added optional timeout to sockets to avoid blocking 
#						  operations
# 2010-07-11 v0.2.1 AN: - change all raise exception (was deprecated), license 
#						  change to LGPL
#------------------------------------------------------------------------------
# TODO:
# - improve tests for Win32 platform (avoid to write EICAR file to disk, or
#   protect it somehow from on-access AV, inside a ZIP/GZip archive isn't enough)
# - use SESSION/END commands to launch several scans in one session
#   (for example provide session mode in a Clamd class)
# - add support for RAWSCAN and MULTISCAN commands ?
# ? Maybe use os.abspath to ensure scan_file uses absolute paths for files
#------------------------------------------------------------------------------
# Documentation : http://www.clamav.net/doc/latest/html/node28.html
"""
pyclamd.py - v0.2.1 - 2010.07.11

Author : Alexandre Norman - norman@xael.org
Licence : LGPL

Usage :


	# Init the connexion to clamd, either :
	# Network
	pyclamd.init_network_socket('localhost', 3310)
	# Unix local socket 
	#pyclamd.init_unix_socket('/var/run/clamd')

	# Get Clamscan version
	print pyclamd.version()

	# Scan a buffer
	print pyclamd.scan_stream(pyclamd.EICAR)

	# Scan a file
	print pyclamd.scan_file('/tmp/test.vir')


Test strings :
^^^^^^^^^^^^
>>> try:
...	 init_unix_socket('/var/run/clamav/clamd.ctl')
... except ScanError:
...	 init_network_socket('localhost', 3310)
... 
>>> ping()
True
>>> version()[:6]=='ClamAV'
True
>>> scan_stream(EICAR)
{'stream': 'Eicar-Test-Signature FOUND'}
>>> open('/tmp/EICAR','w').write(EICAR)
>>> scan_file('/tmp/EICAR')
{'/tmp/EICAR': 'Eicar-Test-Signature'}
>>> contscan_file('/tmp/EICAR')
{'/tmp/EICAR': 'Eicar-Test-Signature'}
>>> import os
>>> os.remove('/tmp/EICAR')

"""


import socket
			
############################################################################

class BufferTooLongError(ValueError):
	pass

class ScanError(IOError):
	pass

# Some global variables
global use_socket
global clamd_HOST
global clamd_PORT
global clamd_SOCKET
global EICAR

# Default values for globals
use_socket = None
clamd_SOCKET = "/var/run/clamav/clamd.ctl"
clamd_HOST = '127.0.0.1'
clamd_PORT = 3310
clamd_timeout = None	#[PL] default timeout for sockets: None = blocking operations

# Eicar test string (encoded for skipping virus scanners)
EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E' \
        'QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n'.decode('base64')

############################################################################

def init_unix_socket(filename="/var/run/clamav/clamd.ctl"):
	"""
	Init pyclamd to use clamd unix local socket 
	
	filename (string): clamd file for local unix socket
	
	return: Nothing

	May raise :
	  - TypeError: if filename is not a string
	  - ValueError: if filename does not allow to ping the server
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET

	# to be backwards compatible and api stable
	try:
		filename = str(filename)
	except:
		raise TypeError('filename should be a string, not "%s"' % 
					type(filename))
	
	use_socket = "UNIX"
	clamd_SOCKET = filename

	ping()

############################################################################

def init_network_socket(host='127.0.0.1', port=3310, timeout=None):
	"""
	Init pyclamd to use clamd network socket 
	
	host (string): clamd server adresse
	port (int): clamd server port
	timeout (int): socket timeout (in seconds, none by default)
	
	return: Nothing

	May raise:
	  - TypeError: if host is not a string or port is not an int
	  - ValueError: if the server can not be pinged
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET
	global clamd_timeout
	

	# to be backwards compatible and api stable
	try:
		filename = str(filename)
	except:
		raise TypeError('filename should be a string, not "%s"' % 
					type(filename))
	
	try:
		port = int(port)
	except:
		raise TypeError('port should be an integer, not "%s"' % type(port))
	
	use_socket = "NET"
	clamd_HOST = host
	clamd_PORT = port
	clamd_timeout = timeout

	ping()
	return

############################################################################

def ping():
	"""
	Send a PING to the clamav server, which should reply
	by a PONG.
	
	return: True if the server replies to PING
	
	May raise:
	  - ScanError: if the server do not reply by PONG
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET


	s = __init_socket__()

	try:
		_send_command(s, 'PING')
		result = _recv_response(s)
		s.close()
	except socket.error:
		raise ScanError('Could not ping clamd server')
	
	if result == 'PONG':
		return True
	else:
		raise ScanError('Could not ping clamd server')


############################################################################

def version():
	"""
	Get Clamscan version

	return: (string) clamscan version
	
	May raise:
	  - ScanError: in case of communication problem
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET
	
	s = __init_socket__()

	try:
		_send_command(s, 'VERSION')
		result = _recv_response(s)
		s.close()
	except socket.error:
		raise ScanError('Could not get version information from server')
	
	return result

############################################################################

def reload():
	"""
	Force Clamd to reload signature database

	return: (string) "RELOADING"
	
	May raise:
	  - ScanError: in case of communication problem
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET
	
	s = __init_socket__()

	try:
		_send_command(s, 'RELOAD')
		result = _recv_response(s)
		s.close()
	except socket.error:
		raise ScanError('Could probably not reload signature database')
	
	return result

############################################################################

def shutdown():
	"""
	Force Clamd to shutdown and exit

	return: nothing
	
	May raise:
	  - ScanError: in case of communication problem
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET
	
	s = __init_socket__()

	try:
		_send_command(s, 'SHUTDOWN')
		result = _recv_response(s)
		s.close()
	except socket.error:
		raise ScanError('Could probably not shutdown clamd')

############################################################################

def scan_file(file):
	"""
	Scan a file or directory given by filename and stop on virus

	file (string) : filename or directory (MUST BE ABSOLUTE PATH !)

	return either :
	  - (dict): {filename1: "virusname"}
	  - None: if no virus found
	
	May raise :
	  - ScanError: in case of communication problem
	  - socket.timeout: if timeout has expired
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET


	s = __init_socket__()

	try:
		_send_command(s, 'SCAN %s' % file)
	except socket.error:
		raise ScanError('Unable to scan %s' % file)
	
	result='...'
	dr={}
	while result:
		try:
			result = _recv_response(s)
		except socket.error:
			raise ScanError('Unable to scan %s' % file)
		
		if len(result) > 0:
			filename, reason, status = _parse_response(result)
			
			if status == 'ERROR':
				raise ScanError(reason)
			elif status == 'FOUND':
				dr[filename] = reason
			
	s.close()
	if not dr:
		return None
	return dr

############################################################################

def contscan_file(file):
	"""
	Scan a file or directory given by filename

	file (string): filename or directory (MUST BE ABSOLUTE PATH !)

	return either :
      - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}
	  - None: if no virus found

	May raise:
	  - ScanError: in case of communication problem
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET


	s = __init_socket__()

	try:
		_send_command(s, 'CONTSCAN %s' % file)
	except socket.error:
		raise ScanError('Unable to scan %s' % file)
		
	result='...'
	dr={}
	while result:
		try:
			result = _recv_response(s)
		except socket.error:
			raise ScanError('Unable to scan %s' % file)
		
		if len(result) > 0:
			filename, reason, status = _parse_response(result)
			
            if status == 'ERROR':
                dr[filename] = ('ERROR', '{0}'.format(reason))

            elif status == 'FOUND':
                dr[filename] = ('FOUND', '{0}'.format(reason))
				
	s.close()
	if not dr:
		return None
	return dr

############################################################################

def scan_stream(buffer):
	"""
	Scan a buffer

	buffer (string): buffer to scan

	return either:
	  - (dict): {filename1: "virusname"}
	  - None: if no virus found

	May raise :
	  - BufferTooLongError: if the buffer size exceeds clamd limits
	  - ScanError: in case of communication problem
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET


	s = __init_socket__()

	try:
		_send_command(s, 'STREAM')
		result = _recv_response(s)
	except socket.error:
		raise ScanError('Unable to scan stream')
	
	try:
		port = int(result.split()[1])
	except:
		raise ScanError('Unable to scan stream')
	
	try:
		n=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		n.connect((clamd_HOST, port))
		
		sended = n.send(buffer)
		n.close()
	except socket.error:
		raise ScanError('Unable to scan stream')
	
	if sended < len(buffer):
		raise BufferTooLongError
		
	result='...'
	dr={}
	while result:
		result = s.recv(20000)
		if len(result) > 0:
			filename, reason, status = _parse_response(result)
			
			if status == 'ERROR':
				raise ScanError(reason)
			elif status == 'FOUND':
				dr[filename] = reason
				
	s.close()
	if not dr:
		return None
	return dr


############################################################################

def __init_socket__():
	"""
	This is for internal use
	"""
	
	global use_socket
	global clamd_HOST
	global clamd_PORT
	global clamd_SOCKET
	global clamd_timeout


	if use_socket == "UNIX":
		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		try:
			s.connect(clamd_SOCKET)
		except socket.error:
			raise ScanError('Could not reach clamd using unix socket (%s)' % 
						(clamd_SOCKET))
	elif use_socket == "NET":
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#[PL] if a global timeout is defined, it is set for the socket
		if clamd_timeout is not None:
			s.settimeout(clamd_timeout)
			
		try:
			s.connect((clamd_HOST, clamd_PORT))
		except socket.error:
			raise ScanError('Could not reach clamd using network (%s, %s)' % 
						(clamd_HOST, clamd_PORT))
	else:
		raise ScanError('Could not reach clamd : connexion not initialised')

	return s


############################################################################

def _send_command(s, cmd):
	"""
	`man clamd` recommends to prefix commands with z, but we will use \n
	terminated strings, as python<->clamd has some problems with \0x00
	"""
	
	cmd = 'n%s\n' % cmd 
	s.send(cmd)
	
def _recv_response(s):
	"""
	receive response from clamd and strip all whitespace characters
	"""
	
	response = s.recv(20000)
	response = response.strip()
	return response




def _parse_response(msg):
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


def __non_regression_test__():
	"""
	This is for internal use
	"""
	import doctest
	doctest.testmod()
	return
	

############################################################################


# MAIN -------------------
if __name__ == '__main__':
	
	__non_regression_test__()




#<EOF>######################################################################
