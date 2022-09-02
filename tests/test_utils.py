import pytest

from pytest_azure.utils import resource_group, credential


def test_resource_group():
    assert not resource_group()


def test_credential():
    cred_keys = ["aad_id", "aad_secret"]
    for key in cred_keys:
        assert key in credential(), key + " not found"


@pytest.mark.skip
def test_aad_access_key(aad_access_key):
    assert "access_token" in aad_access_key


@pytest.mark.skip
def test_management_access_key(management_access_key):
    assert "access_token" in management_access_key
