# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2012-2016 Jean-Marc Martins
# Copyright © 2012-2017 Guillaume Ayoub
# Copyright © 2017-2022 Unrud <unrud@outlook.com>
# Copyright © 2024-2026 Peter Bieringer <pb@bieringer.de>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Radicale.  If not, see <http://www.gnu.org/licenses/>.

"""
Radicale tests with simple requests and authentication.

"""

import base64
import datetime
import logging
import os
import sys
from typing import Any, Iterable, Tuple, Union

import pytest

from radicale import auth, pathutils, xmlutils
from radicale.auth import htpasswd
from radicale.tests import BaseTest


class TestBaseAuthRequests(BaseTest):
    """Tests basic requests with auth.

    We should setup auth for each type before creating the Application object.

    """

    BCRYPT_MAX_PWLEN = htpasswd.Auth.BCRYPT_MAX_PWLEN

    # test for available bcrypt module
    try:
        import bcrypt
    except ImportError:
        has_bcrypt = 0
    else:
        has_bcrypt = 1

    # test for available argon2 module
    try:
        # argon2-cffi is passlib's backend: imported only to fail early if absent
        import argon2 as argon2_backend  # noqa: F401
        from passlib.hash import argon2
    except ImportError:
        has_argon2 = 0
    else:
        has_argon2 = 1

    def _test_htpasswd(self, htpasswd_encryption: str, htpasswd_content: str,
                       test_matrix: Union[str, Iterable[Tuple[str, str, bool]]]
                       = "ascii", delay: float = 0, check: int = 207) -> None:
        """Test htpasswd authentication with user "tmp" and password "bepo" for
           ``test_matrix`` "ascii" or user "😀" and password "🔑" for
           ``test_matrix`` "unicode"."""
        htpasswd_file_path = os.path.join(self.colpath, ".htpasswd")
        encoding: str = self.configuration.get("encoding", "stock")
        with open(htpasswd_file_path, "w", encoding=encoding) as f:
            f.write(htpasswd_content)
        self.configure({"auth": {"type": "htpasswd",
                                 "delay": delay,
                                 "htpasswd_filename": htpasswd_file_path,
                                 "htpasswd_encryption": htpasswd_encryption},
                        "server": {"delay_on_error": 0}})
        if test_matrix == "ascii":
            test_matrix = (("tmp", "bepo", True), ("tmp", "tmp", False),
                           ("tmp", "", False), ("unk", "unk", False),
                           ("unk", "", False), ("", "", False))
        elif test_matrix == "unicode":
            test_matrix = (("😀", "🔑", True), ("😀", "🌹", False),
                           ("😁", "🔑", False), ("😀", "", False),
                           ("", "🔑", False), ("", "", False))
        elif isinstance(test_matrix, str):
            raise ValueError("Unknown test matrix %r" % test_matrix)
        for user, password, valid in test_matrix:
            self.propfind("/", check=check if valid else 401,
                          login="%s:%s" % (user, password))

    def test_htpasswd_plain(self) -> None:
        self._test_htpasswd("plain", "tmp:bepo")

    def test_htpasswd_blacklist_plain(self) -> None:
        self._test_htpasswd("plain", "tmp:be:po", (
            ("tm" + chr(9) + "p", "be:po", True), ("tm" + chr(9) + "p", "bepo", False)), check=401)
        self._test_htpasswd("plain", "tmp:be:po", (
            ("tm'p", "be:po", True), ("tm'p", "bepo", False)), check=401)
        self._test_htpasswd("plain", "tmp:be:po", (
            ('tm"p', "be:po", True), ('tm"p', "bepo", False)), check=401)

    def test_htpasswd_plain_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:bepo")

    def test_htpasswd_plain_password_split(self) -> None:
        self._test_htpasswd("plain", "tmp:be:po", (
            ("tmp", "be:po", True), ("tmp", "bepo", False)))

    def test_htpasswd_plain_unicode(self) -> None:
        if not pathutils.path_supports_unicode(self.colpath):
            check = 401
        else:
            check = 207
        self._test_htpasswd("plain", "😀:🔑", "unicode", check=check)

    def test_htpasswd_strict_plain_unicode(self) -> None:
        """user with unicode chars is not permitted"""
        self.configure({"server": {"validate_user_value": "strict"}})
        if not pathutils.path_supports_unicode(self.colpath):
            check = 401
        else:
            check = 401
        self._test_htpasswd("plain", "😀:🔑", "unicode", check=check)

    def test_htpasswd_minimal_plain_unicode(self) -> None:
        """user with unicode chars is permitted"""
        self.configure({"server": {"validate_user_value": "minimal"}})
        if not pathutils.path_supports_unicode(self.colpath):
            check = 401
        else:
            check = 207
        self._test_htpasswd("plain", "😀:🔑", "unicode", check=check)

    def test_htpasswd_minimal_plain_special(self) -> None:
        """user with special chars is not permitted"""
        self.configure({"server": {"validate_user_value": "minimal"}})
        check = 401
        self._test_htpasswd("plain", "*?*:bepo", "ascii", check=check)

    def test_htpasswd_unicode_plain_unicode(self) -> None:
        """user with unicode symbols is not permitted"""
        self.configure({"server": {"validate_user_value": "unicode-letter"}})
        if not pathutils.path_supports_unicode(self.colpath):
            check = 401
        else:
            check = 401
        self._test_htpasswd("plain", "😀:🔑", "unicode", check=check)

    def test_htpasswd_invalid_user_start_with_at(self) -> None:
        """user start with @ is not permitted"""
        self._test_htpasswd("plain", "@domain.example:test", (
            ("@domain.example", "test", True), ("@domain.example", "test", False)), check=401)

    def test_htpasswd_invalid_user_end_with_at(self) -> None:
        """user end with @ is not permitted"""
        self._test_htpasswd("plain", "domain.example@:test", (
            ("domain.example@", "test", True), ("domain.example@", "test", False)), check=401)

    def test_htpasswd_invalid_user_start_with_encoded_at(self) -> None:
        """user start with encoded @ is not permitted"""
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "@domain.example:test", (
            ("%40domain.example", "test", True), ("%40domain.example", "test", False)), check=401)

    def test_htpasswd_invalid_user_end_with_encoded_at(self) -> None:
        """user end with encoded @ is not permitted"""
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "domain.example@:test", (
            ("domain.example%40", "test", True), ("domain.example%40", "test", False)), check=401)

    def test_htpasswd_invalid_user_with_more_encoded_at(self) -> None:
        """user with more encoded @ is not permitted"""
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "user@group@domain.example:test", (
            ("user%40group%40domain.example", "test", True), ("user%40group%40domain.example", "test", False)), check=401)

    def test_htpasswd_invalid_user_start_with_colon(self) -> None:
        """user start with : is not permitted"""
        try:
            self._test_htpasswd("plain", ":group:test", (
                (":group", "test", True), (":group", "test", False)), check=401)
        except RuntimeError:
            pass
        else:
            raise

    def test_htpasswd_invalid_user_start_with_encoded_colon(self) -> None:
        """user start with encoded : is not permitted"""
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "'%3Adomain.example:test", (
            ("%3Adomain.example", "test", True), ("%3Adomain.example", "test", False)), check=401)

    def test_htpasswd_invalid_user_end_with_encoded_colon(self) -> None:
        """user end with encoded : is not permitted"""
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "domain.example:test", (
            ("domain.example%3A", "test", True), ("domain.example%3A", "test", False)), check=401)

    def test_htpasswd_invalid_user_with_any_encoded_colon(self) -> None:
        """user with any encoded : is not permitted"""
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "user%3Adomain.example:test", (
            ("user%3Adomain.example", "test", True), ("user%3Adomain.example", "test", False)), check=401)

    def test_htpasswd_md5(self) -> None:
        self._test_htpasswd("md5", "tmp:$apr1$BI7VKCZh$GKW4vq2hqDINMr8uv7lDY/")

    def test_htpasswd_md5_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$apr1$BI7VKCZh$GKW4vq2hqDINMr8uv7lDY/")

    def test_htpasswd_md5_unicode(self):
        if not pathutils.path_supports_unicode(self.colpath):
            check = 401
        else:
            check = 207
        self._test_htpasswd(
            "md5", "😀:$apr1$w4ev89r1$29xO8EvJmS2HEAadQ5qy11", "unicode", check=check)

    def test_htpasswd_sha256(self) -> None:
        self._test_htpasswd("sha256", "tmp:$5$i4Ni4TQq6L5FKss5$ilpTjkmnxkwZeV35GB9cYSsDXTALBn6KtWRJAzNlCL/")

    def test_htpasswd_sha256_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$5$i4Ni4TQq6L5FKss5$ilpTjkmnxkwZeV35GB9cYSsDXTALBn6KtWRJAzNlCL/")

    def test_htpasswd_sha256_autodetect_with_rounds(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$5$rounds=2500$9QD/kpJlV71PCXWy$/AbUzxa6kjDWHJ8BLU1hyQUBN/8wsGEf.rNjuKDHA24")

    def test_htpasswd_sha512(self) -> None:
        self._test_htpasswd("sha512", "tmp:$6$3Qhl8r6FLagYdHYa$UCH9yXCed4A.J9FQsFPYAOXImzZUMfvLa0lwcWOxWYLOF5sE/lF99auQ4jKvHY2vijxmefl7G6kMqZ8JPdhIJ/")

    def test_htpasswd_sha512_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$6$3Qhl8r6FLagYdHYa$UCH9yXCed4A.J9FQsFPYAOXImzZUMfvLa0lwcWOxWYLOF5sE/lF99auQ4jKvHY2vijxmefl7G6kMqZ8JPdhIJ/")

    def test_htpasswd_sha512_autodetect_with_rounds(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$6$rounds=2500$A1H/cZUl3CBnsplz$bSKYCDQ/YGR..YhxaZcM1eKmAi/jlnpbENKU8a.9kE95JBIpyUss3.cUyss0xQnhjD4PReN4sAzmdziWmoCsg/")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_2a(self) -> None:
        self._test_htpasswd("bcrypt", "tmp:$2a$10$Mj4A9vMecAp/K7.0fMKoVOk1SjgR.RBhl06a52nvzXhxlT3HB7Reu")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_2a_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$2a$10$Mj4A9vMecAp/K7.0fMKoVOk1SjgR.RBhl06a52nvzXhxlT3HB7Reu")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_2b(self) -> None:
        self._test_htpasswd("bcrypt", "tmp:$2b$12$7a4z/fdmXlBIfkz0smvzW.1Nds8wpgC/bo2DVOb4OSQKWCDL1A1wu")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_2b_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$2b$12$7a4z/fdmXlBIfkz0smvzW.1Nds8wpgC/bo2DVOb4OSQKWCDL1A1wu")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_2y(self) -> None:
        self._test_htpasswd("bcrypt", "tmp:$2y$05$oD7hbiQFQlvCM7zoalo/T.MssV3VNTRI3w5KDnj8NTUKJNWfVpvRq")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_2y_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$2y$05$oD7hbiQFQlvCM7zoalo/T.MssV3VNTRI3w5KDnj8NTUKJNWfVpvRq")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_C10(self) -> None:
        self._test_htpasswd("bcrypt", "tmp:$2y$10$bZsWq06ECzxqi7RmulQvC.T1YHUnLW2E3jn.MU2pvVTGn1dfORt2a")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_C10_autodetect(self) -> None:
        self._test_htpasswd("autodetect", "tmp:$2y$10$bZsWq06ECzxqi7RmulQvC.T1YHUnLW2E3jn.MU2pvVTGn1dfORt2a")

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_unicode(self) -> None:
        if not pathutils.path_supports_unicode(self.colpath):
            check = 401
        else:
            check = 207
        self._test_htpasswd("bcrypt", "😀:$2y$10$Oyz5aHV4MD9eQJbk6GPemOs4T6edK6U9Sqlzr.W1mMVCS8wJUftnW", "unicode", check=check)

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_htpasswd_bcrypt_long(self) -> None:
        import bcrypt
        m = (
             # full available len
             ("tmp", "a" * self.BCRYPT_MAX_PWLEN, True),
             # longer than valid -> same password
             ("tmp", "a" * (self.BCRYPT_MAX_PWLEN + 42), True),
             # shorter that before -> some other password
             ("tmp", "a" * (self.BCRYPT_MAX_PWLEN - 1), False),
             )
        hash = bcrypt.hashpw(("a" * self.BCRYPT_MAX_PWLEN).encode(), bcrypt.gensalt())
        self._test_htpasswd("bcrypt", "tmp:" + hash.decode('utf-8'), m)

    @pytest.mark.skipif(has_bcrypt == 0, reason="No bcrypt module installed")
    def test_bcrypt_hash_long(self) -> None:
        import bcrypt
        salt = bcrypt.gensalt()
        h0 = bcrypt.hashpw(("a" * self.BCRYPT_MAX_PWLEN).encode(), salt)
        try:
            h1 = bcrypt.hashpw(("a" * (self.BCRYPT_MAX_PWLEN + 1)).encode(), salt)
        # bcrypt >= 5, truncated for us
        except ValueError:
            return

        # overlong password produced same hash as maxlen
        assert h0 == h1

    @pytest.mark.skipif(has_argon2 == 0, reason="No argon2 module installed")
    def test_htpasswd_argon2_i(self) -> None:
        self._test_htpasswd("argon2", "tmp:$argon2i$v=19$m=65536,t=3,p=4$NgZg7F1rzRkDoNSaMwag9A$qmsvMKEn5zOXHm8e3O5fKzzcRo0UESwaDr/cETe5YPI")

    @pytest.mark.skipif(has_argon2 == 0, reason="No argon2 module installed")
    def test_htpasswd_argon2_d(self) -> None:
        self._test_htpasswd("argon2", "tmp:$argon2d$v=19$m=65536,t=3,p=4$ufe+txYiJKR0zlkLwVirVQ$MjGqRyVLes38hA6CEOkloMcTYCuLjxCKgIjtfYZ3iSM")

    @pytest.mark.skipif(has_argon2 == 0, reason="No argon2 module installed")
    def test_htpasswd_argon2_id(self) -> None:
        self._test_htpasswd("argon2", "tmp:$argon2id$v=19$m=65536,t=3,p=4$t7bWuneOkdIa45xTqjXGmA$ORnRJyz9kHogJs6bDgZrTBPlzi4+p023PSEABb3xX1g")

    def test_htpasswd_multi(self) -> None:
        self._test_htpasswd("plain", "ign:ign\ntmp:bepo")

    # login cache successful
    def test_htpasswd_login_cache_successful_plain(self, caplog) -> None:
        caplog.set_level(logging.INFO)
        self.configure({"auth": {"cache_logins": "True"}})
        self._test_htpasswd("plain", "tmp:bepo", [("tmp", "bepo", True), ("tmp", "bepo", True)])
        htpasswd_found = False
        htpasswd_cached_found = False
        for line in caplog.messages:
            if line == "Successful login: 'tmp' (htpasswd)":
                htpasswd_found = True
            elif line == "Successful login: 'tmp' (htpasswd/cached)":
                htpasswd_cached_found = True
        if (htpasswd_found is False) or (htpasswd_cached_found is False):
            raise ValueError("Logging misses expected log lines")

    # login cache failed
    def test_htpasswd_login_cache_failed_plain(self, caplog) -> None:
        caplog.set_level(logging.INFO)
        self.configure({"auth": {"cache_logins": "True"}})
        self._test_htpasswd("plain", "tmp:bepo", [("tmp", "bepo1", False), ("tmp", "bepo1", False)])
        htpasswd_found = False
        htpasswd_cached_found = False
        for line in caplog.messages:
            if line == "Failed login attempt from unknown: 'tmp' (htpasswd)":
                htpasswd_found = True
            elif line == "Failed login attempt from unknown: 'tmp' (htpasswd/cached)":
                htpasswd_cached_found = True
        if (htpasswd_found is False) or (htpasswd_cached_found is False):
            raise ValueError("Logging misses expected log lines")

    # login cache failed
    def test_htpasswd_login_cache_failed_delay_plain(self, caplog) -> None:
        caplog.set_level(logging.INFO)
        self.configure({"auth": {"cache_logins": "True"}})
        delay = .3
        delay_min = delay * 0.9  # no random jitter during test
        delay_max = delay + 0.2  # no random jitter during test
        if sys.platform == "darwin" or sys.platform == 'win32':  # no reliable sleep times
            delay_max = delay_max * 2

        time_begin = datetime.datetime.now()
        self._test_htpasswd("plain", "tmp:bepo", [("tmp", "bepo1", False)], delay=delay)
        time_end = datetime.datetime.now()
        time_delta = (time_end - time_begin).total_seconds()
        assert time_delta > delay_min
        assert time_delta < delay_max

        time_begin = datetime.datetime.now()
        self._test_htpasswd("plain", "tmp:bepo", [("tmp", "bepo1", False)], delay=delay)
        time_end = datetime.datetime.now()
        time_delta = (time_end - time_begin).total_seconds()
        assert time_delta > delay_min
        assert time_delta < delay_max

    # htpasswd file cache
    def test_htpasswd_file_cache(self, caplog) -> None:
        self.configure({"auth": {"htpasswd_cache": "True"}})
        self._test_htpasswd("plain", "tmp:bepo")

    # detection of broken htpasswd file entries
    def test_htpasswd_broken(self) -> None:
        for userpass in ["tmp:", ":tmp"]:
            try:
                self._test_htpasswd("plain", userpass)
            except RuntimeError:
                pass
            else:
                raise

    def test_htpasswd_whitespace_user(self) -> None:
        for user in (" tmp", "tmp ", " tmp "):
            if not pathutils.path_supports_trailing_whitespace(self.colpath) and user.endswith(' '):
                check = 401
            else:
                check = 207
            self._test_htpasswd("plain", "%s:bepo" % user, (
                (user, "bepo", True), ("tmp", "bepo", False)), check=check)

    def test_htpasswd_problem_user_none(self) -> None:
        self.configure({"server": {"validate_user_value": "none"}})
        for user in ("tm*p", "tm?p"):
            if not pathutils.path_supports_problematic_chars(self.colpath):
                check = 401
            else:
                check = 207
            self._test_htpasswd("plain", "%s:bepo" % user, (
                (user, "bepo", True), ("tmp", "bepo", False)), check=check)

    def test_htpasswd_problem_user_minimal(self) -> None:
        self.configure({"server": {"validate_user_value": "none"}})
        for user in ("tm*p", "tm?p"):
            if not pathutils.path_supports_problematic_chars(self.colpath):
                check = 401
            else:
                check = 207
            self._test_htpasswd("plain", "%s:bepo" % user, (
                (user, "bepo", True), ("tmp", "bepo", False)), check=check)

    def test_htpasswd_whitespace_password(self) -> None:
        for password in (" bepo", "bepo ", " bepo "):
            self._test_htpasswd("plain", "tmp:%s" % password, (
                ("tmp", password, True), ("tmp", "bepo", False)))

    def test_htpasswd_comment(self) -> None:
        self._test_htpasswd("plain", "#comment\n #comment\n \ntmp:bepo\n\n")

    def test_htpasswd_lc_username(self) -> None:
        self.configure({"auth": {"lc_username": "True"}})
        self._test_htpasswd("plain", "tmp:bepo", (
            ("tmp", "bepo", True), ("TMP", "bepo", True), ("tmp1", "bepo", False)))

    def test_htpasswd_uc_username(self) -> None:
        self.configure({"auth": {"uc_username": "True"}})
        self._test_htpasswd("plain", "TMP:bepo", (
            ("tmp", "bepo", True), ("TMP", "bepo", True), ("TMP1", "bepo", False)))

    def test_htpasswd_strip_domain(self) -> None:
        self.configure({"auth": {"strip_domain": "True"}})
        self._test_htpasswd("plain", "tmp:bepo", (
            ("tmp", "bepo", True), ("tmp@domain.example", "bepo", True), ("tmp1", "bepo", False)))

    def test_htpasswd_email_encoding_url_true(self) -> None:
        self.configure({"auth": {"urldecode_username": "True"}})
        self._test_htpasswd("plain", "tmp@domain.example:bepo", (
            ("tmp", "bepo", False), ("tmp%40domain.example", "bepo", True), ("tmp@domain.example", "bepo", True)))

    def test_htpasswd_email_encoding_url_false(self) -> None:
        self.configure({"auth": {"urldecode_username": "False"}})
        self._test_htpasswd("plain", "tmp@domain.example:bepo", (
            ("tmp", "bepo", False), ("tmp%40domain.example", "bepo", False), ("tmp@domain.example", "bepo", True)))

    def test_remote_user(self) -> None:
        self.configure({"auth": {"type": "remote_user"}})
        _, responses = self.propfind("/", """\
<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
    <prop>
        <current-user-principal />
    </prop>
</propfind>""", REMOTE_USER="test")
        assert responses is not None
        response = responses["/"]
        assert not isinstance(response, int)
        status, prop = response["D:current-user-principal"]
        assert status == 200
        href_element = prop.find(xmlutils.make_clark("D:href"))
        assert href_element is not None and href_element.text == "/test/"

    def test_http_remote_user(self) -> None:
        self.configure({"auth": {"type": "http_remote_user"}})
        _, responses = self.propfind("/", """\
<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
    <prop>
        <current-user-principal />
    </prop>
</propfind>""", HTTP_REMOTE_USER="test")
        assert responses is not None
        response = responses["/"]
        assert not isinstance(response, int)
        status, prop = response["D:current-user-principal"]
        assert status == 200
        href_element = prop.find(xmlutils.make_clark("D:href"))
        assert href_element is not None and href_element.text == "/test/"

    def test_http_x_remote_user(self) -> None:
        self.configure({"auth": {"type": "http_x_remote_user"}})
        _, responses = self.propfind("/", """\
<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
    <prop>
        <current-user-principal />
    </prop>
</propfind>""", HTTP_X_REMOTE_USER="test")
        assert responses is not None
        response = responses["/"]
        assert not isinstance(response, int)
        status, prop = response["D:current-user-principal"]
        assert status == 200
        href_element = prop.find(xmlutils.make_clark("D:href"))
        assert href_element is not None and href_element.text == "/test/"

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def _test_dovecot(
            self, user, password, expected_status, expected_rip=None,
            response=b'FAIL\t1', mech=[b'PLAIN'], broken=None,
            extra_config=None, extra_env=None):
        import socket
        from unittest.mock import DEFAULT, patch

        if extra_env is None:
            extra_env = {}
        if extra_config is None:
            extra_config = {}

        config = {"auth": {"type": "dovecot",
                           "dovecot_socket": "./dovecot.sock"}}
        for toplvl, entries in extra_config.items():
            for key, val in entries.items():
                config[toplvl][key] = val
        self.configure(config)

        if broken is None:
            broken = []

        handshake = b''
        if "version" not in broken:
            handshake += b'VERSION\t'
            if "incompatible" in broken:
                handshake += b'2'
            else:
                handshake += b'1'
            handshake += b'\t2\n'

        if "mech" not in broken:
            handshake += b'MECH\t%b\n' % b' '.join(mech)

        if "duplicate" in broken:
            handshake += b'VERSION\t1\t2\n'

        if "done" not in broken:
            handshake += b'DONE\n'

        sent_rip = None

        def record_sent_data(s, data, flags=None):
            nonlocal sent_rip
            if b'\trip=' in data:
                sent_rip = data.split(b'\trip=')[1].split(b'\t')[0]
            return len(data)

        with patch.multiple(
                'socket.socket',
                connect=DEFAULT,
                send=record_sent_data,
                recv=DEFAULT
                ) as mock_socket:
            if "socket" in broken:
                mock_socket["connect"].side_effect = socket.error(
                        "Testing error with the socket"
                )
            mock_socket["recv"].side_effect = [handshake, response]
            status, _, answer = self.request(
                "PROPFIND", "/",
                HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(
                    ("%s:%s" % (user, password)).encode()).decode(),
                **extra_env)
            assert sent_rip == expected_rip
            assert status == expected_status

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_no_user(self):
        self._test_dovecot("", "", 401)

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_no_password(self):
        self._test_dovecot("user", "", 401)

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_handshake_no_version(self):
        self._test_dovecot("user", "password", 401, broken=["version"])

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_handshake_incompatible(self):
        self._test_dovecot("user", "password", 401, broken=["incompatible"])

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_handshake_duplicate(self):
        self._test_dovecot(
                "user", "password", 207, response=b'OK\t1',
                broken=["duplicate"]
        )

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_handshake_no_mech(self):
        self._test_dovecot("user", "password", 401, broken=["mech"])

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_handshake_unsupported_mech(self):
        self._test_dovecot("user", "password", 401, mech=[b'ONE', b'TWO'])

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_handshake_no_done(self):
        self._test_dovecot("user", "password", 401, broken=["done"])

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_broken_socket(self):
        self._test_dovecot("user", "password", 401, broken=["socket"])

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_auth_good1(self):
        self._test_dovecot("user", "password", 207, response=b'OK\t1')

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_auth_good2(self):
        self._test_dovecot(
                "user", "password", 207, response=b'OK\t1',
                mech=[b'PLAIN\nEXTRA\tTERM']
        )

        self._test_dovecot("user", "password", 207, response=b'OK\t1')

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_auth_bad1(self):
        self._test_dovecot("user", "password", 401, response=b'FAIL\t1')

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_auth_bad2(self):
        self._test_dovecot("user", "password", 401, response=b'CONT\t1')

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_auth_id_mismatch(self):
        self._test_dovecot("user", "password", 401, response=b'OK\t2')

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_remote_addr(self):
        self._test_dovecot("user", "password", 401, expected_rip=b'172.17.16.15',
                           extra_env={
                               'REMOTE_ADDR': '172.17.16.15',
                               'HTTP_X_REMOTE_ADDR': '127.0.0.1',
                           })

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_x_remote_addr(self):
        self._test_dovecot("user", "password", 401, expected_rip=b'172.17.16.15',
                           extra_env={
                               'REMOTE_ADDR': '127.0.0.1',
                               'HTTP_X_REMOTE_ADDR': '172.17.16.15',
                           },
                           extra_config={
                               'auth': {"remote_ip_source": "X-Remote-Addr"},
                           })

    @pytest.mark.skipif(sys.platform == 'win32', reason="Not supported on Windows")
    def test_dovecot_x_remote_addr_whitespace(self):
        self._test_dovecot("user", "password", 401, expected_rip=b'172.17.16.15rip=127.0.0.1',
                           extra_env={
                               'REMOTE_ADDR': '127.0.0.1',
                               'HTTP_X_REMOTE_ADDR': '172.17.16.15\trip=127.0.0.1',
                           },
                           extra_config={
                               'auth': {"remote_ip_source": "X-Remote-Addr"},
                           })

    def test_dovecot_port_config(self) -> None:
        # check for invalid port
        logging.info("Try invalid port: 0")
        try:
            self.configure({"auth": {"dovecot_port": 0}})
        except RuntimeError as e:
            logging.info("Exception: %s", str(e))
        else:
            raise

        # check for invalid port
        logging.info("Try invalid port: 65535")
        try:
            self.configure({"auth": {"dovecot_port": 65535}})
        except RuntimeError as e:
            logging.info("Exception: %s", str(e))
        else:
            raise

        # check for valid port
        logging.info("Try valid port")
        self.configure({"auth": {"dovecot_port": 143}})

    def test_custom(self) -> None:
        """Custom authentication."""
        self.configure({"auth": {"type": "radicale.tests.custom.auth"}})
        self.propfind("/tmp/", login="tmp:")

    def test_none(self) -> None:
        self.configure({"auth": {"type": "none"}})
        self.propfind("/tmp/", login="tmp:")

    def test_denyall(self) -> None:
        self.configure({"auth": {"type": "denyall"}})
        self.propfind("/tmp/", login="tmp:", check=401)

    def test_htpasswd_cache_reload_uses_new_password(self) -> None:
        htpasswd_file_path = os.path.join(self.colpath, ".htpasswd")
        with open(htpasswd_file_path, "w") as f:
            f.write("tmp:bepo\n")
        self.configure({
            "auth": {"type": "htpasswd",
                     "htpasswd_filename": htpasswd_file_path,
                     "htpasswd_encryption": "plain",
                     "htpasswd_cache": "True",
                     "delay": "0"},
            "server": {"delay_on_error": "0"}})
        self.propfind("/", login="tmp:bepo", check=207)
        with open(htpasswd_file_path, "w") as f:
            f.write("tmp:newsecret\n")
        self.propfind("/", login="tmp:newsecret", check=207)
        self.propfind("/", login="tmp:bepo", check=401)

    def test_htpasswd_cache_reread_skips_bad_line_and_reminds(self, monkeypatch, caplog) -> None:
        import radicale.auth.htpasswd as htpasswd_module

        caplog.set_level(logging.WARNING)
        htpasswd_file_path = os.path.join(self.colpath, ".htpasswd")
        with open(htpasswd_file_path, "w") as f:
            f.write("tmp:bepo\n")
        self.configure({
            "auth": {"type": "htpasswd",
                     "htpasswd_filename": htpasswd_file_path,
                     "htpasswd_encryption": "plain",
                     "htpasswd_cache": "True",
                     "delay": "0"},
            "server": {"delay_on_error": "0"}})
        self.propfind("/", login="tmp:bepo", check=207)
        with open(htpasswd_file_path, "w") as f:
            f.write("tmp:bepo\n:broken\n")
        clock = {"now": 1_000_000.0}
        monkeypatch.setattr(htpasswd_module.time, "time", lambda: clock["now"])
        self.propfind("/", login="tmp:bepo", check=207)
        clock["now"] += 61
        caplog.clear()
        self.propfind("/", login="tmp:bepo", check=207)
        assert any("htpasswd file still contains issues (REMINDER" in message
                   for message in caplog.messages)


class _Directory:
    """A mutable fake directory and its controllable clock."""

    EPOCH_NS = 1_000_000_000_000_000_000

    def __init__(self) -> None:
        self.now_ns = self.EPOCH_NS
        self.passwords = {"owner": "secret"}
        self.groups = {"owner": {"staff"}}
        self.calls = 0

    def advance(self, seconds: int) -> None:
        self.now_ns += seconds * 10**9

    def time_ns(self) -> int:
        return self.now_ns

    def login(self, login: str, password: str) -> Tuple[str, set]:
        self.calls += 1
        if self.passwords.get(login) != password:
            return "", set()
        return login, set(self.groups.get(login, set()))


class _DirectoryAuth(auth.BaseAuth):
    """Fake backend that returns the directory's user groups."""

    def __init__(self, configuration, directory: _Directory) -> None:
        super().__init__(configuration)
        self.directory = directory

    def _login_ext_with_groups(self, login: str, password: str,
                               context: auth.AuthContext) -> Tuple[str, set]:
        return self.directory.login(login, password)


class _CredentialsOnlyAuth(auth.BaseAuth):
    """Fake backend that checks a password but supplies no groups."""

    def __init__(self, configuration, directory: _Directory) -> None:
        super().__init__(configuration)
        self.directory = directory

    def _login(self, login: str, password: str) -> str:
        return self.directory.login(login, password)[0]


class TestDirectoryGroupCache(BaseTest):
    """Group membership expires independently of a cached password."""

    def _setup(self, monkeypatch, *, group_expiry: int = 30,
               auth_type: str = "groups",
               credential_expiry: int = 300) -> Any:
        directory = _Directory()
        monkeypatch.setattr(auth.time, "time_ns", directory.time_ns)
        rights_file_path = os.path.join(self.colpath, "rights")
        with open(rights_file_path, "w") as f:
            f.write("""\
[owner]
user: owner
collection: owner(/.*)?
permissions: RrWw
[staff]
groups: staff
collection: shared(/.*)?
permissions: RrWw
""")
        # Use an existing cacheable type name so the cache code runs, then
        # replace the loaded backend with the fake directory.
        plugin_type = "htpasswd" if auth_type == "credentials" else "ldap"
        self.configure({
            "auth": {"type": "denyall", "delay": "0"},
            "rights": {"type": "from_file", "file": rights_file_path},
            "server": {"delay_on_error": "0"}})
        configured = self.configuration.copy()
        configured.update({"auth": {
            "type": plugin_type,
            "cache_logins": "True",
            "cache_successful_logins_expiry": str(credential_expiry),
            "cache_successful_logins_groups_expiry": str(group_expiry)}},
            "test", privileged=True)
        fake = (_CredentialsOnlyAuth if auth_type == "credentials"
                else _DirectoryAuth)
        self.application._auth = fake(configured, directory)
        return directory

    @staticmethod
    def _shared_calendar(colpath: str) -> None:
        # A collection that only the directory group may access.
        shared_path = os.path.join(colpath, "collection-root", "shared")
        calendar_path = os.path.join(shared_path, "calendar")
        os.makedirs(calendar_path)
        with open(os.path.join(shared_path, ".Radicale.props"), "w",
                  encoding="utf-8") as f:
            f.write("{}\n")
        with open(os.path.join(calendar_path, ".Radicale.props"), "w",
                  encoding="utf-8") as f:
            f.write('{"tag": "VCALENDAR"}\n')

    def test_revocation_is_visible_at_group_timeout(self, monkeypatch) -> None:
        directory = self._setup(monkeypatch)
        self._shared_calendar(self.colpath)
        self.propfind("/shared/calendar/", login="owner:secret", check=207)
        calls = directory.calls

        # Inside the group timeout the cached group still grants access.
        directory.groups["owner"] = set()
        directory.advance(29)
        self.propfind("/shared/calendar/", login="owner:secret", check=207)
        assert directory.calls == calls

        # At the timeout the backend runs again. The password remains valid,
        # but the revoked group no longer grants DAV access.
        directory.advance(1)
        self.propfind("/shared/calendar/", login="owner:secret", check=403)
        assert directory.calls == calls + 1
        # The same password still authenticates the user's own principal.
        self.propfind("/owner/", login="owner:secret", check=207)

        # Restoring membership is visible at the next group refresh.
        directory.groups["owner"] = {"staff"}
        directory.advance(30)
        self.propfind("/shared/calendar/", login="owner:secret", check=207)
        assert directory.calls == calls + 2

    def test_zero_group_timeout_refreshes_every_request(self, monkeypatch) -> None:
        directory = self._setup(monkeypatch, group_expiry=0)
        self._shared_calendar(self.colpath)
        calls = directory.calls
        directory.groups["owner"] = set()
        for expected in (403, 403):
            self.propfind("/shared/calendar/", login="owner:secret",
                          check=expected)
        assert directory.calls == calls + 2

    def test_refresh_revalidates_the_password(self, monkeypatch) -> None:
        directory = self._setup(monkeypatch)
        self.propfind("/owner/", login="owner:secret", check=207)
        directory.passwords.pop("owner")
        directory.groups["owner"] = set()
        directory.advance(30)
        # Refresh runs the backend. A now-invalid password is rejected.
        self.propfind("/owner/", login="owner:secret", check=401)
        self.propfind("/owner/", login="owner:secret", check=401)

    def test_wrong_password_keeps_the_valid_cached_entry(self, monkeypatch) -> None:
        directory = self._setup(monkeypatch)
        self.propfind("/owner/", login="owner:secret", check=207)
        calls = directory.calls
        self.propfind("/owner/", login="owner:wrong", check=401)
        # A failed attempt is cached without evicting the valid entry.
        self.propfind("/owner/", login="owner:wrong", check=401)
        assert directory.calls == calls + 1
        self.propfind("/owner/", login="owner:secret", check=207)
        assert directory.calls == calls + 1

    def test_group_timeout_not_used_without_groups(self, monkeypatch) -> None:
        directory = self._setup(monkeypatch, auth_type="credentials",
                                group_expiry=0)
        self.propfind("/owner/", login="owner:secret", check=207)
        calls = directory.calls
        directory.advance(100)
        # A backend without groups keeps the successful entry until the
        # credential timeout, regardless of the group timeout.
        self.propfind("/owner/", login="owner:secret", check=207)
        assert directory.calls == calls

    def test_anonymous_request_does_not_touch_the_directory(self, monkeypatch) -> None:
        directory = self._setup(monkeypatch, group_expiry=0)
        self.propfind("/", check=401)
        assert directory.calls == 0
