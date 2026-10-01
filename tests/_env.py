"""Test-session environment bootstrap.

The installation mode is recorded in the database on first start and can never
change, so the suite must not inherit the developer's ``.env`` database: a
database created in the other mode makes every app-boot test fail with
``INSTALLATION_MODE_MISMATCH``.

Importing this module before any ``lnbits`` import points the session at a
throwaway SQLite database inside a fresh data folder, which also stops a stale
hidden ``data`` directory from leaking state between runs. An explicitly
exported ``LNBITS_DATABASE_URL`` still wins, so the suite can be pointed at
another backend on purpose.
"""

import atexit
import os
import shutil
import tempfile

if "LNBITS_DATABASE_URL" not in os.environ:
    # Empty means "not configured", which selects SQLite.
    os.environ["LNBITS_DATABASE_URL"] = ""

# The suite runs in custodial mode, which tests that exercise the other mode
# override per test. Without this, a developer .env leaks into Settings() and
# breaks assertions about defaults.
os.environ.setdefault("LNBITS_INSTALLATION_MODE", "custodial")

TEST_DATA_FOLDER = os.environ.get("LNBITS_DATA_FOLDER")
if not TEST_DATA_FOLDER:
    TEST_DATA_FOLDER = tempfile.mkdtemp(prefix="lnbits-tests-")
    atexit.register(shutil.rmtree, TEST_DATA_FOLDER, ignore_errors=True)
    os.environ["LNBITS_DATA_FOLDER"] = TEST_DATA_FOLDER
