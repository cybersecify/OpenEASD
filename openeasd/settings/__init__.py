"""Settings package.

`openeasd.settings` is a package (not a single module) so environment-specific
overrides can be layered on `base.py` if ever needed (e.g. a future
`settings/prod.py` that does `from .base import *` then overrides). Today all
environment differences are driven by env vars via `python-decouple` inside
`base.py`, so this `__init__` simply re-exports everything from base — keeping
`DJANGO_SETTINGS_MODULE=openeasd.settings` working unchanged.
"""

from .base import *  # noqa: F401,F403

# Explicit re-export of the private helpers/constants that tests import by name
# (`from openeasd.settings import _validate_secret_key, ...`). `import *` skips
# underscore-prefixed names, so they're listed here deliberately.
from .base import (  # noqa: F401
    _PROFILE_TUNING,
    _resolve_profile,
    _security_settings,
    _validate_secret_key,
)
