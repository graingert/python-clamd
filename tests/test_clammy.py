#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import clamd
from io import BytesIO
from contextlib import contextmanager
import tempfile
import shutil
import os
import stat

import pytest

mine = (stat.S_IREAD | stat.S_IWRITE)
other = stat.S_IROTH
execute = (stat.S_IEXEC | stat.S_IXOTH)


@contextmanager
def mkdtemp(*args, **kwargs):
    temp_dir = tempfile.mkdtemp(*args, **kwargs)
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)


class TestUnixSocket(object):
    kwargs = {}

    def setup(self):
        self.cd = clamd.ClamdUnixSocket(**self.kwargs)

    def test_ping(self):
        assert self.cd.ping()

    def test_version(self):
        assert self.cd.version().startswith("ClamAV")

    def test_reload(self):
        assert self.cd.reload() == 'RELOADING'

    def test_scan(self):
        with tempfile.NamedTemporaryFile('wb', prefix="python-clamd") as f:
            f.write(clamd.EICAR)
            f.flush()
            os.fchmod(f.fileno(), (mine | other))
            expected = {f.name: ('FOUND', 'Eicar-Test-Signature')}

            assert self.cd.scan(f.name) == expected

    def test_unicode_scan(self):
        with tempfile.NamedTemporaryFile('wb', prefix=u"python-clamdλ") as f:
            f.write(clamd.EICAR)
            f.flush()
            os.fchmod(f.fileno(), (mine | other))
            expected = {f.name: ('FOUND', 'Eicar-Test-Signature')}

            assert self.cd.scan(f.name) == expected

    def test_multiscan(self):
        expected = {}
        with mkdtemp(prefix="python-clamd") as d:
            for i in range(10):
                with open(os.path.join(d, "file" + str(i)), 'wb') as f:
                    f.write(clamd.EICAR)
                    os.fchmod(f.fileno(), (mine | other))
                    expected[f.name] = ('FOUND', 'Eicar-Test-Signature')
            os.chmod(d, (mine | other | execute))

            assert self.cd.multiscan(d) == expected

    def test_instream(self):
        expected = {'stream': ('FOUND', 'Eicar-Test-Signature')}
        assert self.cd.instream(BytesIO(clamd.EICAR)) == expected

    def test_insteam_success(self):
        assert self.cd.instream(BytesIO(b"foo")) == {'stream': ('OK', None)}


class TestUnixSocketTimeout(TestUnixSocket):
    kwargs = {"timeout": 20}


def test_cannot_connect():
    with pytest.raises(clamd.ConnectionError):
        clamd.ClamdUnixSocket(path="/tmp/404").ping()
