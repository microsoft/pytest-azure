import json
import os
import uuid

import requests
from azure.core.exceptions import ResourceExistsError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient

API_VERSION = "/api/2.0"


def resource_group():
    """
    Retrieve the Resource Group to target for testing from environmental variables.
    :return:
    """
    return os.getenv("RG")


def credential():
    """
    Load Credentials from environment Azure Account

    Returns: dict of information used for authentication to Azure

    """
    return {
        "AZURE_CLIENT_ID": os.getenv("AZURE_CLIENT_ID", os.getenv("AAD_ID")),
        "object_id": os.getenv("OBJ_ID"),
        "AZURE_CLIENT_SECRET": os.getenv("AZURE_CLIENT_SECRET", os.getenv("aad_secret")),
        "tenant_id": os.getenv("AZURE_TENANT_ID", os.getenv("TENANT_ID")),
        "SUBSCRIPTION_ID": os.getenv("SUBSCRIPTION_ID"),
    }


def aad_access_key():
    """Create a Auth Client for interacting with Databricks

    https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/aad/service-prin-aad-token#--get-an-azure-active-directory-access-token

    curl -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=client_credentials&client_id=<client-id>&resource=<management-endpoint>&client_secret=<app-secret>' \
    https://login.microsoftonline.com/<tenantid>/oauth2/token
    """
    resource = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
    return _get_access_key(resource)


def management_access_key():
    """Create a Auth Client for interacting with Databricks

    https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/aad/service-prin-aad-token#--get-the-azure-management-resource-endpoint-token

    curl -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=client_credentials&client_id=<client-id>&resource=<management-endpoint>&client_secret=<app-secret>' \
    https://login.microsoftonline.com/<tenantid>/oauth2/token
    """
    endpoint = "https://management.core.windows.net/"
    return _get_access_key(endpoint)


def _get_access_key(resource):
    tenant_id = credential()["tenant_id"]
    aad_id = credential()["AZURE_CLIENT_ID"]
    secret = credential()["AZURE_CLIENT_SECRET"]

    url = "https://login.microsoftonline.com/%s/oauth2/token" % tenant_id
    headers = {"content-type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "client_id": aad_id, "client_secret": secret, "resource": resource}

    response = requests.post(url=url, data=data, headers=headers)
    if response.status_code != 200:
        raise ConnectionRefusedError("Unable to create Azure Active Directory access token")
    return response.json()["access_token"]


def get_library_status(aad_access_key, management_access_key):
    """
    https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/libraries#--all-cluster-statuses

    :param credential:
    :param resource_group:
    :param aad_access_key:
    :param management_access_key:
    :return: response from get request
    """
    sub_id = credential()["SUBSCRIPTION_ID"]

    workspace_name = _get_workspace_name()
    instance_id = _get_instance_id(workspace_name, management_access_key)

    api_command = "/libraries/all-cluster-statuses"
    url = f"https://{instance_id}{API_VERSION}{api_command}"

    headers = _get_header(aad_access_key, management_access_key, sub_id, workspace_name)
    return requests.get(url=url, headers=headers)


def execute_db_notebook(notebook, aad_access_key, management_access_key):
    """
    https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/aad/service-prin-aad-token#use-the-management-endpoint-access-token-to-access-the-databricks-rest-api

    :param credential:
    :param notebook:
    :param resource_group:
    :param aad_access_key:
    :param management_access_key:
    :return: response from post request
    """
    sub_id = credential()["SUBSCRIPTION_ID"]

    workspace_name = _get_workspace_name()
    instance_id = _get_instance_id(workspace_name, management_access_key)

    api_command = "/jobs/runs/submit"
    url = f"https://{instance_id}{API_VERSION}{api_command}"

    headers = _get_header(aad_access_key, management_access_key, sub_id, workspace_name)
    data = {
        "run_name": "test-run",
        "new_cluster": {"spark_version": "7.3.x-scala2.12", "node_type_id": "Standard_D3_v2", "num_workers": 1},
        "notebook_task": {"notebook_path": notebook},
    }
    return requests.post(url=url, data=json.dumps(data), headers=headers)


def _get_header(aad_access_key, management_access_key, sub_id, workspace_name):
    return {
        "Authorization": "Bearer " + aad_access_key,
        "X-Databricks-Azure-SP-Management-Token": management_access_key,
        "X-Databricks-Azure-Workspace-Resource-Id": (
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Databricks/workspaces/%s"
            % (sub_id, resource_group(), workspace_name)
        ),
    }


def _get_instance_id(workspace_name, management_access_key):
    """
    Get URL for Databricks Workspace from Resource Name

    https://docs.microsoft.com/en-us/rest/api/databricks/workspaces/get

    :param credential:
    :param resource_group:
    :param workspace_name:
    :return:
    """
    subscription_id = credential()["SUBSCRIPTION_ID"]

    url = (
        "https://management.azure.com/subscriptions/"
        + subscription_id
        + "/resourceGroups/"
        + resource_group()
        + "/providers/Microsoft.Databricks/workspaces/"
        + workspace_name
        + "?api-version=2018-04-01"
    )
    headers = {"Authorization": "Bearer " + management_access_key}

    response = requests.get(url=url, headers=headers)
    if response.status_code != 200:
        raise ConnectionRefusedError("Unable to get Workspace URL")

    return response.json()["properties"]["workspaceUrl"]


def _get_workspace_name():
    return _get_resource_name("Microsoft.Databricks")


def get_key_vault_name():
    return _get_resource_name("Microsoft.KeyVault")


def get_key_vault_names():
    return _get_resource_names("Microsoft.KeyVault")


def get_web_app_name():
    return _get_resource_name("Microsoft.Web")


def get_aks_name():
    return _get_resource_name("Microsoft.ContainerService")


def get_vm_name():
    return _get_resource_name("Microsoft.Compute")


def get_synapse_name():
    """Get Name of Azure Synapse resource name in Resource Group"""
    return _get_resource_name("Microsoft.Synapse")


def get_ml_name():
    """Get Name of Azure Synapse resource name in Resource Group"""
    return _get_resource_name("Microsoft.MachineLearningServices")


def get_compute_client() -> ComputeManagementClient:
    """
    Get new Azure Compute Client using env variables.

    https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-example-virtual-machines

    @return: Authenticated Compute Client
    """
    print(credential())
    tenant_id = credential()["tenant_id"]
    aad_id = credential()["AZURE_CLIENT_ID"]
    secret = credential()["AZURE_CLIENT_SECRET"]
    subscription_id = credential()["SUBSCRIPTION_ID"]

    sp_credential = ClientSecretCredential(
        tenant_id=tenant_id, client_id=aad_id, client_secret=secret, subscription_id=subscription_id
    )
    return ComputeManagementClient(sp_credential, subscription_id)


def _get_resource_name(rp) -> str:
    """
    Get the Name of the first Resource in a Resource Group of the Provided RP type using env variables.

    https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-example-list-resource-groups

    @param rp: Resource Provider Name
    @return (str): Name of Resource
    """
    return _get_resource_names(rp)[0]


def _get_resource_names(rp) -> list:
    """
    Get the Name of the first Resource in a Resource Group of the Provided RP type using env variables.

    https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-example-list-resource-groups

    @param rp: Resource Provider Name
    @return (list): Names of Resources
    """
    print(credential())
    tenant_id = credential()["tenant_id"]
    aad_id = credential()["AZURE_CLIENT_ID"]
    secret = credential()["AZURE_CLIENT_SECRET"]
    subscription_id = credential()["SUBSCRIPTION_ID"]

    sp_credential = ClientSecretCredential(
        tenant_id=tenant_id, client_id=aad_id, client_secret=secret, subscription_id=subscription_id
    )
    resource_client = ResourceManagementClient(sp_credential, subscription_id)

    resource_list = resource_client.resources.list_by_resource_group(resource_group(), expand="createdTime,changedTime")
    column_width = 40

    resource_names = []
    for resource in list(resource_list):
        print(
            f"{resource.name:<{column_width}}{resource.type:<{column_width}}"
            f"{str(resource.created_time):<{column_width}}{str(resource.changed_time):<{column_width}}"
        )

        if rp in resource.type:
            resource_names.append(resource.name)
    return resource_names


def get_key_vault_secret(secret, key_vault=None, rbac=True):
    """
    Get Secret from Key Vault

    Set Access Policy for SP if it is not already set.

    @param secret: Name of Secret to retrieve
    @param key_vault: Name of Key Vault to retrieve secret from
    @return: secret in plain text
    """
    key_vault = key_vault or get_key_vault_name()
    if rbac:
        _set_rbac_access_key_vault(key_vault)

    secret_client = SecretClient("https://" + key_vault + ".vault.azure.net/", DefaultAzureCredential())
    return secret_client.get_secret(secret).value


def _set_rbac_access_key_vault(key_vault=None):
    key_vault = key_vault or get_key_vault_name()

    subscription_id = credential()["SUBSCRIPTION_ID"]
    object_id = credential()["object_id"]

    auth_client = AuthorizationManagementClient(DefaultAzureCredential(), subscription_id)
    role = "00482a5a-887f-4fb3-b363-3b7fe8e74483"  # Key Vault Administrator
    role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role}"
    try:
        auth_client.role_assignments.create(
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group()}/providers/Microsoft.KeyVault/vaults/{key_vault}",
            uuid.uuid4(),
            {
                "role_definition_id": role_definition_id,
                "principal_id": object_id,
            },
        )
    except ResourceExistsError:
        pass  # Role Assignment already exists


def _set_policy():
    # Vault/request information
    subscription_id = credential()["SUBSCRIPTION_ID"]
    group_name = resource_group()
    vault_name = get_key_vault_name()
    operation_kind = "add"

    management_uri = (
        "https://management.azure.com/"
        + "subscriptions/{}/"
        + "resourceGroups/{}/"
        + "providers/Microsoft.KeyVault/"
        + "vaults/{}/"
        + "accessPolicies/{}"
        + "?api-version=2019-09-01"
    )

    # Payload and PUT it
    usable_uri = management_uri.format(subscription_id, group_name, vault_name, operation_kind)
    data = {
        "properties": {
            "accessPolicies": [
                {
                    "tenantId": credential()["tenant_id"],
                    "objectId": "74e90cb6-ca34-4ebc-aeb7-662bc8024053",
                    "permissions": {
                        "secrets": ["get"],
                    },
                }
            ]
        }
    }

    headers = {"Authorization": "Bearer " + management_access_key()}

    response = requests.put(usable_uri, json=data, headers=headers)
    if response.status_code != 200:
        raise ConnectionRefusedError(
            "Unable to set Azure Key Vault Permission. Response: " + str(response.status_code) + str(response.json())
        )
    return response


def post_api_test(api_config, api_app_url, headers):
    """
    Test POST API

    @param api_config: Configuration object with route and body
    @param api_app_url: Endpoint URL
    @param headers: headers including auth information
    """
    route = api_config.route
    url = api_app_url + route
    body = api_config.body
    params = api_config.params
    if params:
        url = api_app_url + route + "?" + params
        response = requests.post(url, headers=headers)
    else:
        response = requests.post(url, headers=headers, data=body)
    return response


def get_api_test(api_config, api_app_url, headers):
    """
    Test GET API

    @param api_config: Configuration object with route and body
    @param api_app_url: Endpoint URL
    @param headers: headers including auth information
    """
    route = api_config.route
    url = api_app_url + route
    if api_config.params:
        url = api_app_url + route + "?" + api_config.params

    response = requests.get(url, headers=headers)
    return response
