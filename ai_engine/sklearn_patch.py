import sys
from unittest.mock import MagicMock

# Patch Windows AppLocker policy block on unused _hist_gradient_boosting C-extensions
if 'sklearn.ensemble._hist_gradient_boosting' not in sys.modules:
    sys.modules['sklearn.ensemble._hist_gradient_boosting'] = MagicMock()
    sys.modules['sklearn.ensemble._hist_gradient_boosting.gradient_boosting'] = MagicMock()
