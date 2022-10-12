"""
(c) Microsoft. All rights reserved.
"""

import os

from microsoft.industrialai.utils.test_utils import get_key_vault_secret
from microsoft.industrialai.vaults import (
    AzureKeyVaultConfiguration,
    DatabricksSecretConfiguration,
    DotEnvConfiguration,
    SecretNotFoundError,
    SecretConflictError,
    OperationNotSupported,
    VaultAcquisition,
)
from microsoft.industrialai.vaults.configurations import AzureMLVaultConfiguration
from mocks import *


@pytest.mark.unittest
def test_mocked_datbricks_vault():
    db_utils_injection()

    dbvault = VaultAcquisition.get_vault(DatabricksSecretConfiguration("secrets"))

    # Ensure right config type
    assert isinstance(dbvault.get_configuration(), DatabricksSecretConfiguration)

    # Test get - mock ensures dbutils is in globals
    result = dbvault.get_secret("foo")
    assert isinstance(result, str)

    # Does not support create so always a false
    assert dbvault.create_secret("foo", "bar") == False

    # Does not support delete so always an exception
    with pytest.raises(OperationNotSupported):
        dbvault.delete_secret("foo")

    # Does not support list so always an exception
    with pytest.raises(OperationNotSupported):
        dbvault.list_secrets()

    db_utils_undo_injection()


@pytest.mark.unittest
def test_mocked_azureml_vault():
    az_vault_scope = AzMlMockWorkspace()

    azvault = VaultAcquisition.get_vault(AzureMLVaultConfiguration(az_vault_scope))

    # Ensure right config type
    assert isinstance(azvault.get_configuration(), AzureMLVaultConfiguration)

    # Test list
    result = azvault.list_secrets()
    assert isinstance(result, list)

    # Test get - mock ensures dbutils is in globals
    result = azvault.get_secret("foo")
    assert isinstance(result, str)

    # Does not support create so always a false
    assert azvault.create_secret("foo", "bar") == True

    with pytest.raises(OperationNotSupported):
        azvault.delete_secret("foo")


@pytest.mark.unittest
def test_mocked_azure_vault(mock_az_vault_good):
    az_vault_scope = {"vault": "YOUR_KEY_VAULT_NAME", "sub": "YOUR_AZURE_SUB_ID"}

    azvault = VaultAcquisition.get_vault(AzureKeyVaultConfiguration(az_vault_scope))

    # Ensure right config type
    assert isinstance(azvault.get_configuration(), AzureKeyVaultConfiguration)

    # Test get - mock ensures dbutils is in globals
    result = azvault.get_secret("foo")
    assert isinstance(result, str)

    # Does not support create so always a false
    assert azvault.create_secret("foo", "bar")

    azvault.delete_secret("foo")


@pytest.mark.unittest
def test_mocked_azure_vault2(mock_az_vault_bad):
    az_vault_scope = {"vault": "YOUR_KEY_VAULT_NAME", "sub": "YOUR_AZURE_SUB_ID"}

    azvault = VaultAcquisition.get_vault(AzureKeyVaultConfiguration(az_vault_scope))

    # Ensure right config type
    assert isinstance(azvault.get_configuration(), AzureKeyVaultConfiguration)

    # Test get -
    with pytest.raises(SecretNotFoundError):
        result = azvault.get_secret("foo", True)

    # Does not support create so always a false
    with pytest.raises(SecretConflictError):
        azvault.create_secret("foo", "bar")

    with pytest.raises(SecretNotFoundError):
        azvault.delete_secret("foo")


@pytest.mark.unittest
def test_dotenv_vault():
    path = os.path.split(__file__)[0]

    envvault = VaultAcquisition.get_vault(DotEnvConfiguration(path))

    # Ensure right config type
    assert isinstance(envvault.get_configuration(), DotEnvConfiguration)

    assert envvault.create_secret("foo", "bar") == True

    result = envvault.get_secret("foo")
    assert result == "bar"

    envvault.delete_secret("foo")
    with pytest.raises(SecretNotFoundError):
        result = envvault.get_secret("foo", True)

    os.remove(os.path.join(path, ".env"))


@pytest.mark.unittest
def test_key_vault_tests(mock_az_vault_good):
    assert get_key_vault_secret("foo", "YOUR_KEY_VAULT_NAME") == "mockSecret"
