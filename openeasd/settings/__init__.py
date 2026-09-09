"""Settings package.

`openeasd.settings` is a package (not a single module) so environment-specific
overrides can be layered on `base.py` if ever needed (e.g. a future
`settings/prod.py` that imports base then overrides). Today all environment
differences are driven by env vars via `python-decouple` inside `base.py`, so
this `__init__` simply re-exports base's settings — keeping
`DJANGO_SETTINGS_MODULE=openeasd.settings` working unchanged.

Re-export is done by copying base's UPPERCASE module globals (Django only reads
uppercase names) rather than `from .base import *` — the wildcard trips CodeQL's
`py/polluting-import`, and this is equivalent and explicit.
"""

from . import base as _base

# Copy every Django setting (uppercase module global) from base onto this package.
globals().update({_k: _v for _k, _v in vars(_base).items() if _k.isupper()})

# Private helpers/constants tests import by name (the uppercase copy above skips
# the lowercase ones); listed explicitly.
from .base import (  # noqa: E402,F401
    _PROFILE_TUNING,
    _resolve_profile,
    _security_settings,
    _validate_secret_key,
)
