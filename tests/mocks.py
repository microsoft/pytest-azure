"""
(c) Microsoft. All rights reserved.
"""
import os

import pytest
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError
from azure.mgmt.authorization.operations import RoleAssignmentsOperations
from microsoft.industrialai.vaults import (
    DatabricksSecretsVault,
    AzureVaultSecret,
    AzureKeyVault,
)
from microsoft.industrialai.loginvalidation import AzureLoginValidation


# Mocks/monkeypatch for tests - Azure Key Vault
def az_vault_secret_dummy(self, name: str, secret_id: str):
    az_secret = AzureVaultSecret(name, secret_id)
    az_secret.add_version_info("id_dummy_longer", True, "Mock Value")
    return az_secret


def fail_az_vault_secret_dummy(self, name: str, secret_id: str):
    return None


def az_secret_create(self, sec_name, sec_value):
    class MockSecret:
        def __init__(self, name):
            self.name = name

    return MockSecret(sec_name)


def az_secret_get(self, sec_name):
    class MockSecret:
        def __init__(self, name):
            self.name = name
            self.value = "mockSecret"

    return MockSecret(sec_name)


def az_secret_create_throw(self, sec_name, sec_value):
    raise ResourceExistsError("no good my frield")


def az_secret_delete(self, sec_name):
    class MockPoller:
        def result(self):
            return "I'm gone!"

    return MockPoller()


def az_role_assignment_create(self, scope, role_assignment_name, parameters, **kwargs):
    class MockPoller:
        def result(self):
            return "I'm gone!"

    return MockPoller()


def az_secret_delete_throw(self, sec_name):
    raise ResourceNotFoundError("Not here")


def az_provide_cred(boolval, strval):
    return "I'm not None"


# AzureML Workspace/Keyvault mock


class AzMlMockWorkspace:
    def get_default_keyvault(self):
        class VaultMock:
            def list_secrets(self):
                return [{"name": "secret1"}, {"name": "secret2"}]

            def set_secret(self, sec_name, sec_value):
                pass

            def get_secret(self, sec_name):
                return "Here I am"

        return VaultMock()


# Azure Key Vault Fixtures
@pytest.fixture
def mock_az_vault_good(monkeypatch):
    monkeypatch.setattr(AzureLoginValidation, "get_viable_credential", az_provide_cred)
    monkeypatch.setattr(AzureKeyVault, "_collect_secret_info", az_vault_secret_dummy)
    monkeypatch.setattr(SecretClient, "set_secret", az_secret_create)
    monkeypatch.setattr(SecretClient, "get_secret", az_secret_get)
    monkeypatch.setattr(SecretClient, "begin_delete_secret", az_secret_delete)
    monkeypatch.setattr(RoleAssignmentsOperations, "create", az_role_assignment_create)

    os.environ["SUBSCRIPTION_ID"] = "YOUR_AZURE_SUB_ID"
    os.environ["AAD_ID"] = "SAMPLE_GUID"


@pytest.fixture
def mock_az_vault_bad(monkeypatch):
    monkeypatch.setattr(AzureLoginValidation, "get_viable_credential", az_provide_cred)
    monkeypatch.setattr(AzureKeyVault, "_collect_secret_info", fail_az_vault_secret_dummy)
    monkeypatch.setattr(SecretClient, "set_secret", az_secret_create_throw)
    monkeypatch.setattr(SecretClient, "begin_delete_secret", az_secret_delete_throw)


# Mocks/monkeypatch for tests - Databricks
def db_utils_injection():
    if "dbutils" not in DatabricksSecretsVault.get_secret.__globals__:

        class MockSecrets:
            def get(self, **kwargs):
                return "Mocked key"

        class MockDBUtils:
            def __init__(self):
                self.secrets = MockSecrets()

        DatabricksSecretsVault.get_secret.__globals__["dbutils"] = MockDBUtils()


def db_utils_undo_injection():
    """This doesn't appear to fix it"""
    if "dbutils" in DatabricksSecretsVault.get_secret.__globals__:
        del DatabricksSecretsVault.get_secret.__globals__["dbutils"]
