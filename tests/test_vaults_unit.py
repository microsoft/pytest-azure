"""
(c) Microsoft. All rights reserved.
"""

from microsoft.industrialai.utils.test_utils import get_key_vault_secret
from mocks import *


@pytest.mark.unittest
def test_key_vault_tests(mock_az_vault_good):
    assert get_key_vault_secret("foo", "YOUR_KEY_VAULT_NAME") == "mockSecret"
