# clamd

`clamd` is a portable Python module to use the ClamAV anti-virus engine on Windows, Linux, MacOSX and other platforms. It requires a running instance of the clamd daemon.

### History

This is a fork of `pyClamd` (v0.2.0) created by Philippe Lagadec and published on [his](http://www.decalage.info/en/python/pyclamd) website, which in turn is a slightly improved version of `pyClamd` (v0.1.1) created by Alexandre Norman and published on [his](http://xael.org/norman/python/pyclamd/) website.

## Installation

Make sure you have installed both `clamav` engine and `clamav-daemon`, for instance, you can install it on Ubuntu by running the following commands:

```bash
apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
freshclam  # update the database
systemctl start clamav-daemon
```

```bash
pip install clamd
```

## Usage/Examples

To use with a Unix socket:

```python
>>> import clamd
>>> cd = clamd.ClamdUnixSocket()
>>> cd.ping()
'PONG'
>>> cd.version()                             # doctest: +ELLIPSIS
'ClamAV ...
>>> cd.reload()
'RELOADING'
```

To scan a file:

```python
>>> open('/tmp/EICAR','wb').write(clamd.EICAR)
>>> cd.scan('/tmp/EICAR')
{'/tmp/EICAR': ('FOUND', 'Eicar-Test-Signature')}
```

To scan a stream:
```python
>>> from io import BytesIO
>>> cd.instream(BytesIO(clamd.EICAR))
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```
`clamav` daemon runs under `clamav` user and might not be able to scan files owned by other users or root user, in this case you can use `fdscan` function which opens a file and then passes the file descriptor to `clamav` daemon:

```python
>>> open('/tmp/EICAR','wb').write(clamd.EICAR)
>>> cd.fdscan('/tmp/EICAR')
{'/tmp/EICAR': ('FOUND', 'Eicar-Test-Signature')}
```

## License

clamd is released as open-source software under the LGPL license.
