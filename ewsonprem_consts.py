# File: ewsonprem_consts.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Parameter constants
EWSONPREM_JSON_DEVICE_URL = "url"
EWSONPREM_JSON_SUBJECT = "subject"
EWSONPREM_JSON_FROM = "sender"
EWSONPREM_JSON_INT_MSG_ID = "internet_message_id"
EWSONPREM_JSON_EMAIL = "email"
EWSONPREM_JSON_FOLDER = "folder"
EWSONPREM_JSON_BODY = "body"
EWSONPREM_JSON_QUERY = "query"
EWSONPREM_JSON_RANGE = "range"
EWSONPREM_JSON_ID = "id"
EWSONPREM_JSON_GROUP = "group"
EWSONPREM_JSON_INGEST_EMAIL = "ingest_email"
EWS_JSON_CONTAINER_ID = "container_id"
EWS_JSON_VAULT_ID = "vault_id"

EWS_JSON_POLL_USER = "poll_user"
EWS_JSON_USE_IMPERSONATE = "use_impersonation"
EWS_JSON_AUTH_TYPE = "auth_type"
EWS_JSON_CLIENT_ID = "client_id"
EWS_JSON_CLIENT_SECRET = "client_secret"  # pragma: allowlist secret
EWS_JSON_POLL_FOLDER = "poll_folder"
EWS_JSON_INGEST_MANNER = "ingest_manner"
EWS_JSON_FIRST_RUN_MAX_EMAILS = "first_run_max_emails"
EWS_JSON_POLL_MAX_CONTAINERS = "max_containers"
EWS_JSON_DONT_IMPERSONATE = "dont_impersonate"
EWS_JSON_IMPERSONATE_EMAIL = "impersonate_email"
EWS_JSON_AUTH_URL = "authority_url"
EWS_JSON_FED_PING_URL = "fed_ping_url"
EWS_JSON_FED_VERIFY_CERT = "fed_verify_server_cert"
EWS_JSON_IS_PUBLIC_FOLDER = "is_public_folder"

# Success and error messages constants
EWSONPREM_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
EWSONPREM_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
EWSONPREM_ERR_SERVER_CONNECTION = "Connection failed"
EWSONPREM_ERR_FROM_SERVER = "API failed. Status code: {code}. Message: {message}"
EWSONPREM_ERR_JSON_PARSE = "Unable to parse reply, raw string reply: '{raw_text}'"

EWSONPREM_MAX_END_OFFSET_VAL = 2147483646
EWS_O365_RESOURCE = "https://outlook.office365.com"
EWS_LOGIN_URL = "https://login.windows.net"

EWS_MODIFY_CONFIG = "Toggling the impersonation configuration on the asset might help, "
EWS_MODIFY_CONFIG += "or login user does not have privileges to the mailbox."
EWS_MODIFY_CONFIG += " Please check the asset configuration parameters"

EWS_ASSET_CORRUPTED = "ERROR: The state file for this asset might get corrupted. Please delete asset file located at "
EWS_ASSET_CORRUPTED += "(/opt/phantom/local_data/app_states/a73f6d32-c9d5-4fec-b024-43876700daa6/<asset_id>_state.json) "
EWS_ASSET_CORRUPTED += "and run the test connectivity again"
EWS_INGEST_LATEST_EMAILS = "latest first"
EWS_INGEST_OLDEST_EMAILS = "oldest first"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Authentication type constants
AUTH_TYPE_AZURE = "Azure"
AUTH_TYPE_AZURE_INTERACTIVE = "Azure (interactive)"
AUTH_TYPE_FEDERATED = "Federated"
AUTH_TYPE_BASIC = "Basic"
