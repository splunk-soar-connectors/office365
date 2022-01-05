# File: ewsonprem_connector.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#

# ==========================================================
# To Grant access to a user's mailbox to another, read the command found at the following location
# https://technet.microsoft.com/en-us/library/bb124097(v=exchg.160).aspx
# Basically it's the use of the Add-MailboxPermission cmdlet
# >Add-MailboxPermission "User Two" -User "Phantom User" -AccessRights FullAccess
# to grant the Phantom User access to User Two's mail box
# The following command grants the administrator access to everybody's mail box
# Get-Mailbox -ResultSize unlimited -Filter {(RecipientTypeDetails -eq 'UserMailbox') -and (Alias -ne 'Admin')} | Add-MailboxPermission -User admin@contoso.com -AccessRights fullaccess -InheritanceType all # noqa
# Apparently it should work for exchange online _also_
# Removing privileges is done by running
# Remove-MailboxPermission -Identity Test1 -User Test2 -AccessRights FullAccess -InheritanceType All
# This example removes user Administrator's full access rights to user Phantom's mailbox.
# >Remove-MailboxPermission -Identity Phantom -User Administrator -AccessRights FullAccess -InheritanceType All
# ==========================================================

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as ph_rules
import phantom.utils as ph_utils

# THIS Connector imports
from ewsonprem_consts import *
import ews_soap

import requests
import json
import xmltodict
import os
import uuid
from requests.auth import AuthBase
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict
try:
    from urllib.parse import urlparse, quote_plus
except ImportError:
    from urllib import quote_plus
    from urlparse import urlparse

import base64
from datetime import datetime, timedelta
import re
from process_email import ProcessEmail
from email.parser import HeaderParser
from email.header import decode_header
import email
import quopri
import outlookmsgfile
from bs4 import UnicodeDammit
import six

import time

from request_handler import RequestStateHandler, _get_dir_name_from_app_name  # noqa


app_dir = os.path.dirname(os.path.abspath(__file__))
os.sys.path.insert(0, '{}/dependencies/ews_dep'.format(app_dir))  # noqa
from requests_ntlm import HttpNtlmAuth  # noqa


class RetVal3(tuple):
    def __new__(cls, val1, val2=None, val3=None):
        return tuple.__new__(RetVal3, (val1, val2, val3))


class RetVal2(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal2, (val1, val2))


OFFICE365_APP_ID = "a73f6d32-c9d5-4fec-b024-43876700daa6"
EXCHANGE_ONPREM_APP_ID = "badc5252-4a82-4a6d-bc53-d1e503857124"


class OAuth2TokenAuth(AuthBase):

    def __init__(self, token, token_type="Bearer"):
        self._token = token
        self._token_type = token_type

    def __call__(self, r):
        # modify and return the request
        r.headers['Authorization'] = "{0} {1}".format(self._token_type, self._token)
        return r


class EWSOnPremConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_DELETE_EMAIL = "delete_email"
    ACTION_ID_UPDATE_EMAIL = "update_email"
    ACTION_ID_COPY_EMAIL = "copy_email"
    ACTION_ID_MOVE_EMAIL = "move_email"
    ACTION_ID_BLOCK_SENDER = "block_sender"
    ACTION_ID_UNBLOCK_SENDER = "unblock_sender"
    ACTION_ID_EXPAND_DL = "expand_dl"
    ACTION_ID_RESOLVE_NAME = "resolve_name"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_GET_EMAIL = "get_email"
    REPLACE_CONST = "C53CEA8298BD401BA695F247633D0542"

    def __init__(self):
        """ """
        self.__id_to_name = {}

        # Call the BaseConnectors init first
        super(EWSOnPremConnector, self).__init__()

        self._session = None

        # Target user in case of impersonation
        self._target_user = None

        self._state_file_path = None
        self._state = {}

        self._impersonate = False
        self._less_data = False
        self._dup_data = 0

    def _handle_preprocess_scipts(self):

        config = self.get_config()
        script = config.get('preprocess_script')

        self._preprocess_container = lambda x: x

        if script:
            try:  # Try to load in script to preprocess artifacts
                import importlib.util
                preprocess_methods = importlib.util.spec_from_loader('preprocess_methods', loader=None)
                self._script_module = importlib.util.module_from_spec(preprocess_methods)
                exec(script, self._script_module.__dict__)
            except Exception as e:
                self.save_progress("Error loading custom script. Error: {}".format(str(e)))
                return self.set_status(phantom.APP_ERROR, EWSONPREM_ERR_CONNECTIVITY_TEST)

            try:
                self._preprocess_container = self._script_module.preprocess_container
            except Exception:
                self.save_progress("Error loading custom script. Does not contain preprocess_container function")
                return self.set_status(phantom.APP_ERROR, EWSONPREM_ERR_CONNECTIVITY_TEST)

        return phantom.APP_SUCCESS

    def _get_ping_fed_request_xml(self, config):

        try:
            ret_val = "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' "
            ret_val += "xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' "
            ret_val += "xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>"
            ret_val += "<s:Header>"
            ret_val += "<wsse:Action s:mustUnderstand='1'>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsse:Action>"
            ret_val += "<wsse:messageID>urn:uuid:7f45785a-9691-451e-b3ff-30ab463af64c</wsse:messageID>"
            ret_val += "<wsse:ReplyTo><wsse:Address>http://www.w3.org/2005/08/addressing/anonymous</wsse:Address></wsse:ReplyTo>"
            ret_val += "<wsse:To s:mustUnderstand='1'>"
            ret_val += config[EWS_JSON_FED_PING_URL].split('?')[0]
            ret_val += "</wsse:To>"
            ret_val += "<o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>"
            ret_val += "<u:Timestamp>"
            ret_val += "<u:Created>"

            dt_now = datetime.utcnow()
            dt_plus = dt_now + timedelta(minutes=10)

            dt_now_str = "{0}Z".format(dt_now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])
            dt_plus_str = "{0}Z".format(dt_plus.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])

            ret_val += dt_now_str
            ret_val += "</u:Created>"
            ret_val += "<u:Expires>"
            ret_val += dt_plus_str
            ret_val += "</u:Expires>"
            ret_val += "</u:Timestamp>"
            ret_val += "<o:UsernameToken>"
            ret_val += "<wsse:Username>"
            ret_val += config[phantom.APP_JSON_USERNAME]
            ret_val += "</wsse:Username>"
            ret_val += "<o:Password>"
            ret_val += config[phantom.APP_JSON_PASSWORD]
            ret_val += "</o:Password>"
            ret_val += "</o:UsernameToken>"
            ret_val += "</o:Security>"
            ret_val += "</s:Header>"
            ret_val += "<s:Body>"
            ret_val += "<trust:RequestSecurityToken xmlns:trust='http://docs.oasis-open.org/ws-sx/ws-trust/200512'>"
            ret_val += "<wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>"
            ret_val += "<wsse:EndpointReference><wsse:Address>urn:federation:MicrosoftOnline</wsse:Address></wsse:EndpointReference>"
            ret_val += "</wsp:AppliesTo>"
            ret_val += "<trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>"
            ret_val += "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>"
            ret_val += "</trust:RequestSecurityToken>"
            ret_val += "</s:Body>"
            ret_val += "</s:Envelope>"
        except Exception as e:
            return (None, "Unable to create request xml data. Error: {0}".format(str(e)))

        return (ret_val, "Done")

    def _set_federated_auth(self, config):

        ret_val, message = self._check_password(config)
        if phantom.is_fail(ret_val):
            self.save_progress(message)
            return (None, message)

        required_params = [EWS_JSON_CLIENT_ID, EWS_JSON_FED_PING_URL, EWS_JSON_AUTH_URL, EWS_JSON_FED_VERIFY_CERT]

        for required_param in required_params:
            if (required_param not in config):
                return (None, "ERROR: {0} is a required parameter for Azure/Federated Authentication, please specify one.".format(required_param))

        client_id = config[EWS_JSON_CLIENT_ID]

        # create the xml request that we need to send to the ping fed
        fed_request_xml, message = self._get_ping_fed_request_xml(config)

        if (fed_request_xml is None):
            return (None, message)

        # Now create the request to the server
        headers = {'Content-Type': 'application/soap_xml; charset=utf8'}

        url = config[EWS_JSON_FED_PING_URL]

        # POST the request
        try:
            r = requests.post(url, data=fed_request_xml, headers=headers, verify=config[EWS_JSON_FED_VERIFY_CERT])
        except Exception as e:
            return (None, "Unable to send POST to ping url: {0}, Error: {1}".format(url, str(e)))

        if (r.status_code != 200):
            return (None, "POST to ping url failed. Status Code: {0}".format(r.status_code))

        # process the xml response
        xml_response = r.text
        start_pos = xml_response.find('<saml:Assertion')
        end_pos = xml_response.find('</saml:Assertion>') + len('</saml:Assertion>')

        # validate that the saml assertion is present
        if (start_pos == -1 or end_pos == -1):
            return (None, "Could not find Saml Assertion")

        saml_assertion = xml_response[start_pos:end_pos]

        # base64 encode the assertion
        saml_assertion_encoded = base64.encodestring(saml_assertion.encode('utf8'))

        # Now work on sending th assertion, to get the token
        url = '{0}/oauth2/token'.format(config[EWS_JSON_AUTH_URL])

        # headers
        client_req_id = str(uuid.uuid4())
        headers = {'Accept': 'application/json', 'client-request-id': client_req_id, 'return-client-request-id': 'True'}

        # URL
        parsed_auth_url = urlparse(self._base_url)

        # Form data
        data = {
                'resource': '{0}://{1}'.format(parsed_auth_url.scheme, parsed_auth_url.netloc),
                'client_id': client_id,
                'grant_type': 'urn:ietf:params:oauth:grant-type:saml1_1-bearer',
                'assertion': saml_assertion_encoded,
                'scope': 'openid' }

        try:
            r = requests.post(url, data=data, headers=headers)
        except Exception as e:
            return (None, "Failed to acquire token. POST request failed for {0}, Error: {1}".format(url, str(e)))

        if (r.status_code != 200):
            return (None, "POST to office365 url failed. Status Code: {0}".format(r.status_code))

        resp_json = None
        try:
            resp_json = r.json()
        except Exception as e:
            return (None, "Unable to parse auth token response as JSON. Error: {0}".format(str(e)))

        if ('token_type' not in resp_json):
            return (None, "token_type not found in response from server")

        if ('access_token' not in resp_json):
            return (None, "token not found in response from server")

        self.save_progress("Got Access Token")

        return (OAuth2TokenAuth(resp_json['access_token'], resp_json['token_type']), "")

    def _make_rest_calls_to_phantom(self, action_result, url):

        r = requests.get(url, verify=False)
        if not r:
            message = 'Status Code: {0}'.format(r.status_code)
            if (r.text):
                message += " Error from Server: {0}".format(r.text.replace('{', '{{').replace('}', '}}'))
            return (action_result.set_status(phantom.APP_ERROR, "Error retrieving system info, {0}".format(message)), None)

        try:
            resp_json = r.json()
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Error processing response JSON", e), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _get_phantom_base_url_ews(self, action_result):

        ret_val, resp_json = self._make_rest_calls_to_phantom(action_result, self.get_phantom_base_url() + 'rest/system_info')

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        phantom_base_url = resp_json.get('base_url')
        if (not phantom_base_url):
            return (action_result.set_status(phantom.APP_ERROR, "Phantom Base URL is not configured, please configure it in System Settings"), None)

        phantom_base_url = phantom_base_url.strip("/")

        return (phantom.APP_SUCCESS, phantom_base_url)

    def _get_asset_name(self, action_result):

        ret_val, resp_json = self._make_rest_calls_to_phantom(action_result, self.get_phantom_base_url() + 'rest/asset/{0}'.format(self.get_asset_id()))

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        asset_name = resp_json.get('name')
        if (not asset_name):
            return (action_result.set_status(phantom.APP_ERROR, "Error retrieving asset name"), None)

        return (phantom.APP_SUCCESS, asset_name)

    def _get_url_to_app_rest(self, action_result=None):
        if (not action_result):
            action_result = ActionResult()
        # get the phantom ip to redirect to
        ret_val, phantom_base_url = self._get_phantom_base_url_ews(action_result)
        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), action_result.get_message())
        # get the asset name
        ret_val, asset_name = self._get_asset_name(action_result)
        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), action_result.get_message())
        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']
        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = "{0}/rest/handler/{1}_{2}/{3}".format(phantom_base_url, app_dir_name, app_json['appid'], asset_name)
        return (phantom.APP_SUCCESS, url_to_app_rest)

    def _azure_int_auth_initial(self, client_id, rsh, client_secret):
        state = rsh.load_state()
        asset_id = self.get_asset_id()

        ret_val, message = self._get_url_to_app_rest()
        if phantom.is_fail(ret_val):
            return (None, message)

        app_rest_url = message

        request_url = 'https://login.microsoftonline.com/common/oauth2'

        proxy = {}
        if 'HTTP_PROXY' in os.environ:
            proxy['http'] = os.environ.get('HTTP_PROXY')

        if 'HTTPS_PROXY' in os.environ:
            proxy['https'] = os.environ.get('HTTPS_PROXY')

        state['proxy'] = proxy
        state['client_id'] = client_id
        state['redirect_url'] = app_rest_url
        state['request_url'] = request_url
        # This handling is for the python version 3, working fine with both the python version 2 and 3
        client_secret = client_secret.encode('ascii')
        client_secret = base64.b64encode(client_secret)
        state['client_secret'] = client_secret.decode('ascii')

        rsh.save_state(state)
        self.save_state(state)
        self.save_progress("Redirect URI: {}".format(app_rest_url))
        params = {
            'response_type': 'code',
            'response_mode': 'query',
            'client_id': client_id,
            'state': asset_id,
            'redirect_uri': app_rest_url
        }
        url = requests.Request('GET', request_url + '/authorize', params=params).prepare().url
        url += '&'

        self.save_progress("To continue, open this link in a new tab in your browser")
        self.save_progress(url)
        for _ in range(0, 60):
            time.sleep(5)
            state = rsh.load_state()
            oauth_token = state.get('oauth_token')
            if oauth_token:
                break
            elif state.get('error'):
                return (None, "Error retrieving OAuth token")
        else:
            return (None, "Timed out waiting for login")

        self._state['oauth_token'] = oauth_token
        return (OAuth2TokenAuth(oauth_token['access_token'], oauth_token['token_type']), "")

    def _azure_int_auth_refresh(self, client_id, client_secret):

        oauth_token = self._state.get('oauth_token')

        if not oauth_token:
            return (None, "Unable to get refresh token. Has Test Connectivity been run?")

        if client_id != self._state.get('client_id', ''):
            return (None, "Client ID has been changed. Please run Test Connectivity again")

        refresh_token = oauth_token['refresh_token']

        request_url = 'https://login.microsoftonline.com/common/oauth2/token'
        body = {
            'grant_type': 'refresh_token',
            'resource': 'https://outlook.office365.com/',
            'client_id': client_id,
            'refresh_token': refresh_token,
            'client_secret': client_secret
        }
        try:
            r = requests.post(request_url, data=body)
        except Exception as e:
            return (None, "Error refreshing token: {}".format(str(e)))

        try:
            oauth_token = r.json()
        except Exception:
            return (None, "Error retrieving OAuth Token")

        self._state['oauth_token'] = oauth_token
        return (OAuth2TokenAuth(oauth_token['access_token'], oauth_token['token_type']), "")

    def _set_azure_int_auth(self, config):

        client_id = config.get(EWS_JSON_CLIENT_ID)
        client_secret = config.get(EWS_JSON_CLIENT_SECRET)

        if (not client_id):
            return (None, "ERROR: {0} is a required parameter for Azure Authentication, please specify one.".format(EWS_JSON_CLIENT_ID))

        if (not client_secret):
            return (None, "ERROR: {0} is a required parameter for Azure Authentication, please specify one.".format(EWS_JSON_CLIENT_SECRET))

        asset_id = self.get_asset_id()
        rsh = RequestStateHandler(asset_id)  # Use the states from the OAuth login

        try:
            self._state = rsh._decrypt_state(self._state)
        except Exception:
            return (None, EWS_ASSET_CORRUPTED)

        if self.get_action_identifier() != phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            self.debug_print("Try to generate token from refresh token")
            ret = self._azure_int_auth_refresh(client_id, client_secret)
        else:
            self.debug_print("Try to generate token from authorization code")
            ret = self._azure_int_auth_initial(client_id, rsh, client_secret)

        self._state['client_id'] = client_id
        self._state = rsh._encrypt_state(self._state)
        self.save_state(self._state)

        # NOTE: This state is in the app directory, it is
        #  different than the app state (i.e. self._state)

        rsh.delete_state()

        return ret

    def _set_azure_auth(self, config):

        ret_val, message = self._check_password(config)
        if phantom.is_fail(ret_val):
            self.save_progress(message)
            return (None, message)

        username = config[phantom.APP_JSON_USERNAME]
        password = config[phantom.APP_JSON_PASSWORD]
        client_id = config.get(EWS_JSON_CLIENT_ID)
        client_secret = config.get(EWS_JSON_CLIENT_SECRET)

        if (not client_id):
            return (None, "ERROR: {0} is a required parameter for Azure Authentication, please specify one.".format(EWS_JSON_CLIENT_ID))

        if (not client_secret):
            return (None, "ERROR: {0} is a required parameter for Azure Authentication, please specify one.".format(EWS_JSON_CLIENT_SECRET))

        client_req_id = str(uuid.uuid4())

        headers = {'Accept': 'application/json', 'client-request-id': client_req_id, 'return-client-request-id': 'True'}
        url = "{0}/common/UserRealm/{1}".format(EWS_LOGIN_URL, username)
        params = {'api-version': '1.0'}

        try:
            r = self._session.get(url, params=params, headers=headers)
        except Exception as e:
            return (None, str(e))

        if (r.status_code != 200):
            return (None, r.text)

        resp_json = None
        try:
            resp_json = r.json()
        except Exception as e:
            return (None, str(e))

        domain = resp_json.get('domain_name')
        if (not domain):
            return (None, "Did not find domain in response. Cannot continue")

        headers = {'client-request-id': client_req_id, 'return-client-request-id': 'True'}
        url = "{0}/{1}/oauth2/token".format(EWS_LOGIN_URL, domain)
        params = None

        parsed_base_url = urlparse(self._base_url)

        data = {
                'resource': '{0}://{1}'.format(parsed_base_url.scheme, parsed_base_url.netloc),
                'client_id': client_id,
                'username': username,
                'password': password,
                'grant_type': 'password',
                'scope': 'openid',
                'client_secret': client_secret }

        try:
            r = self._session.post(url, params=params, headers=headers, data=data, verify=True)
        except Exception as e:
            return (None, str(e))

        if (r.status_code != 200):
            return (None, self._clean_str(r.text))

        resp_json = None
        try:
            resp_json = r.json()
        except Exception as e:
            return (None, str(e))

        if ('token_type' not in resp_json):
            return (None, "token_type not found in response from server")

        if ('access_token' not in resp_json):
            return (None, "token not found in response from server")

        self.save_progress("Got Access Token")

        return (OAuth2TokenAuth(resp_json['access_token'], resp_json['token_type']), "")

    def _check_password(self, config):
        if phantom.APP_JSON_PASSWORD not in list(config.keys()):
            return phantom.APP_ERROR, "Password not present in asset configuration"
        return phantom.APP_SUCCESS, ''

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        try:
            if not float(parameter).is_integer():
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the '{0}' parameter".format(key)), None

            parameter = int(parameter)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the '{0}' parameter".format(key)), None

        if not allow_zero and parameter <= 0:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a non-zero positive integer in the '{0}' parameter".format(key)), None
        elif allow_zero and parameter < 0:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the '{0}' parameter".format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
        except Exception:
            error_code = "Error code unavailable"
            error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _get_string(self, input_str, charset):

        try:
            if input_str:
                input_str = UnicodeDammit(input_str).unicode_markup.encode(charset).decode(charset)
        except Exception:
            self.debug_print("Error occurred while converting to string with specific encoding")

        return input_str

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def initialize(self):
        """ Called once for every action, all member initializations occur here"""

        self._state = self.load_state()

        config = self.get_config()

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {'Content-Type': 'text/xml; charset=utf-8', 'Accept': 'text/xml'}

        self._session = requests.Session()

        auth_type = config.get(EWS_JSON_AUTH_TYPE, "Basic")

        self._base_url = config[EWSONPREM_JSON_DEVICE_URL]

        message = ''

        if (auth_type == AUTH_TYPE_AZURE):
            self.save_progress("Using Azure AD authentication")
            self._session.auth, message = self._set_azure_auth(config)
        elif (auth_type == AUTH_TYPE_AZURE_INTERACTIVE):
            self.save_progress("Using Azure AD authentication (interactive)")
            self._session.auth, message = self._set_azure_int_auth(config)
        elif (auth_type == AUTH_TYPE_FEDERATED):
            self.save_progress("Using Federated authentication")
            self._session.auth, message = self._set_federated_auth(config)
        else:
            # Make sure username and password are set
            ret_val, message = self._check_password(config)
            if phantom.is_fail(ret_val):
                self.save_progress(message)
                return ret_val

            password = config[phantom.APP_JSON_PASSWORD]
            username = config[phantom.APP_JSON_USERNAME]
            username = username.replace('/', '\\')

            self._session.auth = HTTPBasicAuth(username, password)

            # depending on the app, it's either basic or NTML
            if (self.get_app_id() != OFFICE365_APP_ID):
                self.save_progress("Using NTLM authentication")
                # use NTLM (Exchange on Prem)
                self._session.auth = HttpNtlmAuth(username, password)
            else:
                self.save_progress("Using HTTP Basic authentication")

        if (not self._session.auth):
            return self.set_status(phantom.APP_ERROR, message)

        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        # The host member extacts the host from the URL, is used in creating status messages
        self._host = self._base_url[self._base_url.find('//') + 2:]

        self._impersonate = config[EWS_JSON_USE_IMPERSONATE]

        ret = self._handle_preprocess_scipts()
        if phantom.is_fail(ret):
            return ret

        return phantom.APP_SUCCESS

    def _get_error_details(self, resp_json):
        """ Function that parses the error json recieved from the device and placed into a json"""

        error_details = {"message": "Not Found", "code": "Not supplied"}

        if (not resp_json):
            return error_details

        error_details['message'] = resp_json.get('m:MessageText', 'Not Specified')
        error_details['code'] = resp_json.get('m:ResponseCode', 'Not Specified')

        return error_details

    def _create_aqs(self, subject, sender, body):
        aqs_str = ""
        if (subject):
            aqs_str += "subject:\"{}\" ".format(subject)
        if (sender):
            aqs_str += "from:\"{}\" ".format(sender)
        if (body):
            aqs_str += "body:\"{}\" ".format(body)

        return aqs_str.strip()

    # TODO: Should change these function to be parameterized, instead of one per type of request
    def _check_get_attachment_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:GetAttachmentResponse']['m:ResponseMessages']['m:GetAttachmentResponseMessage']

    def _check_getitem_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:GetItemResponse']['m:ResponseMessages']['m:GetItemResponseMessage']

    def _check_find_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:FindItemResponse']['m:ResponseMessages']['m:FindItemResponseMessage']

    def _check_delete_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:DeleteItemResponse']['m:ResponseMessages']['m:DeleteItemResponseMessage']

    def _check_update_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:UpdateItemResponse']['m:ResponseMessages']['m:UpdateItemResponseMessage']

    def _check_copy_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:CopyItemResponse']['m:ResponseMessages']['m:CopyItemResponseMessage']

    def _check_markasjunk_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:MarkAsJunkResponse']['m:ResponseMessages']['m:MarkAsJunkResponseMessage']

    def _check_move_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:MoveItemResponse']['m:ResponseMessages']['m:MoveItemResponseMessage']

    def _check_expand_dl_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:ExpandDLResponse']['m:ResponseMessages']['m:ExpandDLResponseMessage']

    def _check_findfolder_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:FindFolderResponse']['m:ResponseMessages']['m:FindFolderResponseMessage']

    def _check_getfolder_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:GetFolderResponse']['m:ResponseMessages']['m:GetFolderResponseMessage']

    def _check_resolve_names_response(self, resp_json):
        return resp_json['s:Envelope']['s:Body']['m:ResolveNamesResponse']['m:ResponseMessages']['m:ResolveNamesResponseMessage']

    def _parse_fault_node(self, result, fault_node):

        fault_code = fault_node.get('faultcode', {}).get('#text', 'Not specified')
        fault_string = fault_node.get('faultstring', {}).get('#text', 'Not specified')

        return result.set_status(phantom.APP_ERROR,
                'Error occurred, Code: {0} Detail: {1}'.format(fault_code, fault_string))

    def _clean_xml(self, input_xml):

        # But before we do that clean up the xml, MS is known to send invalid xml chars, that it's own msxml library deems as invalid
        # https://support.microsoft.com/en-us/kb/315580
        replace_regex = r"&#x([0-8]|[b-cB-C]|[e-fE-F]|1[0-9]|1[a-fA-F]);"
        clean_xml, number_of_substitutes = re.subn(replace_regex, '', input_xml)

        self.debug_print("Cleaned xml with {0} substitutions".format(number_of_substitutes))

        return clean_xml

    def _get_http_error_details(self, r):

        if ('text/xml' in r.headers.get('Content-Type', '')):
            # Try a xmltodict parse
            try:
                resp_json = xmltodict.parse(self._clean_xml(r.text))

                # convert from OrderedDict to plain dict
                resp_json = json.loads(json.dumps(resp_json))
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
                self.debug_print("Error occurred while parsing the HTTP error response. {0}".format(error_text))
                return "Unable to parse error details"

            try:
                return resp_json['s:Envelope']['s:Body']['s:Fault']['detail']['e:Message']['#text']
            except Exception:
                pass

        return ""

    def _make_rest_call(self, result, data, check_response, data_string=False):
        """ Function that makes the REST call to the device, generic function that can be called from various action handlers
        Needs to return two values, 1st the phantom.APP_[SUCCESS|ERROR], 2nd the response
        """

        resp_json = None

        if ((self._impersonate) and (not self._target_user)):
            return (result.set_status(phantom.APP_ERROR, "Impersonation is required, but target user not set. Cannot continue execution"), None)

        if (self._impersonate):
            data = ews_soap.add_to_envelope(data, self._target_user)
        else:
            data = ews_soap.add_to_envelope(data)

        data = ews_soap.get_string(data)

        # Make the call
        try:
            r = self._session.post(self._base_url, data=data, headers=self._headers, timeout=60, verify=True)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return (result.set_status(phantom.APP_ERROR, EWSONPREM_ERR_SERVER_CONNECTION, error_text), resp_json)

        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data({'r_status_code': r.status_code})
            result.add_debug_data({'r_text': r.text if r else 'r is None'})
            result.add_debug_data({'r_headers': r.headers})

        if (not (200 <= r.status_code <= 399)):
            # error
            detail = self._get_http_error_details(r)
            if r.status_code == 401:
                detail = "{0}. {1}".format(detail, EWS_MODIFY_CONFIG)
            if detail:
                return (result.set_status(phantom.APP_ERROR,
                    "Call failed with HTTP Code: {0}. Reason: {1}. Details: {2}".format(r.status_code, r.reason, detail)), None)
            return (result.set_status(phantom.APP_ERROR,
                    "Call failed with HTTP code: {0}. Reason: {1}.".format(r.status_code, r.reason)), None)

        # Try a xmltodict parse
        try:
            resp_json = xmltodict.parse(self._clean_xml(r.text))

            # convert from OrderedDict to plain dict
            resp_json = json.loads(json.dumps(resp_json))
        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = EWSONPREM_ERR_JSON_PARSE.format(raw_text=r.text)
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return (result.set_status(phantom.APP_ERROR, msg_string, error_text), resp_json)

        # Check if there is a fault node present
        fault_node = resp_json.get('s:Envelope', {}).get('s:Body', {}).get('s:Fault')

        if (fault_node):
            return (self._parse_fault_node(result, fault_node), None)

        # Now try getting the response message
        try:
            resp_message = check_response(resp_json)
        except Exception as e:
            msg_string = EWSONPREM_ERR_JSON_PARSE.format(raw_text=r.text)
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return (result.set_status(phantom.APP_ERROR, msg_string, error_text), resp_json)

        if (type(resp_message) != dict):
            return (phantom.APP_SUCCESS, resp_message)

        resp_class = resp_message.get('@ResponseClass', '')

        if (resp_class == 'Error'):
            return (result.set_status(phantom.APP_ERROR, EWSONPREM_ERR_FROM_SERVER.format(**(self._get_error_details(resp_message)))), resp_json)

        return (phantom.APP_SUCCESS, resp_message)

    def _test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers."""

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, email_infos = self._get_email_infos_to_process(0, 1, action_result)

        # Process errors
        if (phantom.is_fail(ret_val)):

            # Dump error messages in the log
            self.debug_print(action_result.get_message())

            # action_result.append_to_message(EWS_MODIFY_CONFIG)

            # Set the status of the complete connector result
            action_result.set_status(phantom.APP_ERROR, action_result.get_message())

            # Append the message to display
            self.save_progress(EWSONPREM_ERR_CONNECTIVITY_TEST)

            # return error
            return phantom.APP_ERROR

        # Set the status of the connector result
        self.save_progress(EWSONPREM_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_child_folder_infos(self, user, action_result, parent_folder_info):

        step_size = 500
        folder_infos = list()

        for curr_step_value in range(0, 10000, step_size):

            curr_range = "{0}-{1}".format(curr_step_value, curr_step_value + step_size - 1)

            input_xml = ews_soap.xml_get_children_info(user, parent_folder_id=parent_folder_info['id'], query_range=curr_range)

            ret_val, resp_json = self._make_rest_call(action_result, input_xml, self._check_findfolder_response)

            if (phantom.is_fail(ret_val)):
                return (action_result.get_status(), None)

            total_items = resp_json.get('m:RootFolder', {}).get('@TotalItemsInView', '0')

            if (total_items == '0'):
                # total_items gives the total items in the view, not just items returned in the current call
                return (action_result.set_status(phantom.APP_ERROR, "Children not found, possibly not present."), None)

            folders = resp_json.get('m:RootFolder', {}).get('t:Folders', {}).get('t:Folder')

            if (not folders):
                return (action_result.set_status(phantom.APP_ERROR, "Folder information not found in response, possibly not present"), None)

            if (type(folders) != list):
                folders = [folders]

            folder_infos.extend([{
                'id': x['t:FolderId']['@Id'],
                'display_name': x['t:DisplayName'],
                'children_count': x['t:ChildFolderCount'],
                'folder_path': self._extract_folder_path(x.get('t:ExtendedProperty'))} for x in folders])

            curr_folder_len = len(folders)
            if (curr_folder_len < step_size):

                # got less than what we asked for, so looks like we got all that we wanted
                break

            '''
            for folder_info in folder_infos:
                if (int(folder_info['children_count']) <= 0):
                    continue
                curr_ar = ActionResult()
                ret_val, child_folder_infos = self._get_child_folder_infos(user, curr_ar, folder_info)
                if (ret_val):
                    folder_infos.extend(child_folder_infos)
            '''

        return (phantom.APP_SUCCESS, folder_infos)

    def _cleanse_key_names(self, input_dict):

        if (not input_dict):
            return input_dict

        if (type(input_dict) != dict):
            return input_dict

        for k, v in list(input_dict.items()):
            if (k.find(':') != -1):
                new_key = k.replace(':', '_')
                input_dict[new_key] = v
                del input_dict[k]
            if (type(v) == dict):
                input_dict[new_key] = self._cleanse_key_names(v)
            if (type(v) == list):

                new_v = []

                for curr_v in v:
                    new_v.append(self._cleanse_key_names(curr_v))

                input_dict[new_key] = new_v

        return input_dict

    def _validate_range(self, email_range, action_result):

        try:
            mini, maxi = (int(x) for x in email_range.split('-'))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse the range. Please specify the range as min_offset-max_offset")

        if (mini < 0) or (maxi < 0):
            return action_result.set_status(phantom.APP_ERROR, "Invalid min or max offset value specified in range")

        if (mini > maxi):
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value, min_offset greater than max_offset")

        if (maxi > EWSONPREM_MAX_END_OFFSET_VAL):
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value. The max_offset value cannot be greater than {0}".format(EWSONPREM_MAX_END_OFFSET_VAL))

        return (phantom.APP_SUCCESS)

    def _process_query(self, action_result, params, flag=False):

        subject = params.get("subject")
        sender = params.get("sender")
        body = params.get("body")
        int_msg_id = params.get("int_msg_id")
        aqs = params.get("aqs")
        is_public_folder = params.get("is_public_folder", False)
        user = params.get("user")
        folder_path = params.get("folder_path")
        email_range = params.get("email_range", "0-10")
        ignore_subfolders = params.get("ignore_subfolders")

        folder_infos = []
        if (folder_path):
            # get the id of the folder specified
            ret_val, folder_info = self._get_folder_info(user, folder_path, action_result, is_public_folder)
        else:
            ret_val, folder_info = self._get_root_folder_id(action_result, is_public_folder)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status(), None

        parent_folder_info = folder_info
        folder_infos.append(folder_info)

        if (not ignore_subfolders):
            if (int(parent_folder_info['children_count']) != 0):
                ret_val, child_folder_infos = self._get_child_folder_infos(user, action_result, parent_folder_info=parent_folder_info)
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status(), None
                folder_infos.extend(child_folder_infos)
        items_matched = 0
        msg_items = list()

        num_folder_ids = len(folder_infos)

        self.save_progress('Will be searching in {0} folder{1}', num_folder_ids, 's' if (num_folder_ids > 1) else '')

        for i, folder_info in enumerate(folder_infos):

            folder_id = folder_info['id']

            ar_folder = ActionResult()
            if (aqs):
                data = ews_soap.get_search_request_aqs([folder_id], aqs, email_range)
            else:
                data = ews_soap.get_search_request_filter([folder_id], subject=subject, sender=sender,
                                                          body=body, int_msg_id=int_msg_id, email_range=email_range)

            ret_val, resp_json = self._make_rest_call(ar_folder, data, self._check_find_response)

            # Process errors
            if (phantom.is_fail(ret_val)):
                self.debug_print("Rest call failed: {0}".format(ar_folder.get_message()))
                continue

            resp_json = resp_json.get('m:RootFolder')

            if (not resp_json):
                self.debug_print('Result does not contain RootFolder key')
                continue

            items = resp_json.get('t:Items')

            if (items is None):
                self.debug_print("There are no items in the response")
                continue

            items = resp_json.get('t:Items', {}).get('t:Message', [])

            if (type(items) != list):
                items = [items]

            items_matched += len(items)

            for curr_item in items:
                self._cleanse_key_names(curr_item)
                curr_item['folder'] = folder_info['display_name']
                curr_item['folder_path'] = folder_info.get('folder_path')

                if flag:
                    msg_items.append(curr_item)
                else:
                    action_result.add_data(curr_item)

        if flag:
            return phantom.APP_SUCCESS, msg_items

        return phantom.APP_SUCCESS, items_matched

    def _run_query_aqs(self, param):
        """ Action handler for the 'run query' action"""

        action_result = self.add_action_result(ActionResult(dict(param)))

        subject = param.get(EWSONPREM_JSON_SUBJECT, "")
        sender = param.get(EWSONPREM_JSON_FROM, "")
        body = param.get(EWSONPREM_JSON_BODY, "")
        int_msg_id = param.get(EWSONPREM_JSON_INT_MSG_ID, "")
        aqs = param.get(EWSONPREM_JSON_QUERY, "")
        is_public_folder = param.get(EWS_JSON_IS_PUBLIC_FOLDER, False)

        try:
            if aqs:
                UnicodeDammit(aqs).unicode_markup
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Parameter validation failed for the AQS query. {0}".format(error_text))
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the query. Unicode value found.")

        if (not subject and not sender and not aqs and not body and not int_msg_id):
            return action_result.set_status(phantom.APP_ERROR, "Please specify at-least one search criteria")

        # Use parameters to create an aqs string
        '''
        if (not aqs):
            aqs = self._create_aqs(subject, sender, body)
        '''

        self.debug_print("AQS_STR: {}".format(aqs))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)
        user = param[EWSONPREM_JSON_EMAIL]

        folder_path = param.get(EWSONPREM_JSON_FOLDER)

        self._target_user = user
        ignore_subfolders = param.get('ignore_subfolders', False)

        # self.save_progress("Searching in {0}\\{1}{2}".format(
        #     self._clean_str(user),
        #     folder_path if folder_path else 'All Folders',
        #     ' (and the children)' if (not ignore_subfolders) else ''))

        email_range = param.get(EWSONPREM_JSON_RANGE, "0-10")

        ret_val = self._validate_range(email_range, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        params = {
            "subject": subject,
            "sender": sender,
            "body": body,
            "int_msg_id": int_msg_id,
            "aqs": aqs,
            "is_public_folder": is_public_folder,
            "user": user,
            "folder_path": folder_path,
            "email_range": email_range,
            "ignore_subfolders": ignore_subfolders
        }
        ret_val, items_matched = self._process_query(action_result, params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({'emails_matched': items_matched})
        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_container_id(self, email_id):

        email_id = quote_plus(email_id)

        url = self.get_phantom_base_url() + 'rest/container?_filter_source_data_identifier="{0}"&_filter_asset={1}'.format(email_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Unable to query Email container", error_text)
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Container results, not proper", error_text)
            return None

        return container_id

    def _get_email_data_from_container(self, container_id, action_result):

        email_data = None
        email_id = None
        resp_data = {}
        try:
            ret_val, resp_data, status_code = self.get_container_info(container_id)
        except ValueError as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return RetVal3(action_result.set_status(phantom.APP_ERROR, 'Validation failed for the container_id. {0}'.format(error_text)), email_data, email_id)

        if (phantom.is_fail(ret_val)):
            return RetVal3(action_result.set_status(phantom.APP_ERROR, str(resp_data)), email_data, email_id)

        # Keep pylint happy
        resp_data = dict(resp_data)

        email_data = resp_data.get('data', {}).get('raw_email')
        email_id = resp_data['source_data_identifier']

        if (not email_data):
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                "Container does not seem to be created by the same app, raw_email data not found."), None, None)

        if ((not email_id.endswith('=')) and (not ph_utils.is_sha1(email_id))):
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                "Container does not seem to be created by the same app, email id not in proper format."), None, None)

        return RetVal3(phantom.APP_SUCCESS, email_data, email_id)

    def _get_email_data_from_vault(self, vault_id, action_result):

        file_path = None

        try:
            success, message, file_info = ph_rules.vault_info(vault_id=vault_id)
            file_info = list(file_info)[0]
            file_path = file_info.get('path')
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print(error_text)
            return RetVal2(action_result.set_status(phantom.APP_ERROR, "Could not get file path for vault item"), None)

        if not file_path:
            return RetVal2(action_result.set_status(phantom.APP_ERROR, "Could not get file path for vault item"), None)

        try:
            mail = outlookmsgfile.load(file_path)
        except UnicodeDecodeError as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Failed to parse message. {0}".format(error_text)), None
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Failed to parse message. {0}".format(error_text))
            return action_result.set_status(phantom.APP_ERROR, "Failed to parse message. Please check if the provided file is valid msg file."), None

        return phantom.APP_SUCCESS, mail

    def _decode_subject(self, subject, charset):
        # Decode subject unicode
        decoded_subject = ''
        subject = subject.split('?=\r\n\t=')
        for sub in subject:
            if '?UTF-8?B?' in sub:
                sub = sub.replace('?UTF-8?B?', '').replace('?=', '')
                sub = base64.b64decode(sub)
            elif '?UTF-8?Q?' in sub:
                sub = sub.replace('?UTF-8?Q?', '').replace('?=', '')
                sub = quopri.decodestring(sub)
            sub = sub.decode(charset)
            decoded_subject = decoded_subject + sub

        return decoded_subject

    def _decode_uni_string(self, input_str, def_name):

        # try to find all the decoded strings, we could have multiple decoded strings
        # or a single decoded string between two normal strings separated by \r\n
        # YEAH...it could get that messy
        encoded_strings = re.findall(r'=\?.*\?=', input_str, re.I)

        # return input_str as is, no need to do any conversion
        if (not encoded_strings):
            return input_str

        # get the decoded strings
        try:
            decoded_strings = [decode_header(x)[0] for x in encoded_strings]
            decoded_strings = [{'value': x[0], 'encoding': x[1]} for x in decoded_strings]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            self.debug_print("Decoding: {0}. Error code: {1}. Error message: {2}".format(encoded_strings, error_code, error_msg))
            return def_name

        # convert to dict for safe access, if it's an empty list, the dict will be empty
        decoded_strings = dict(enumerate(decoded_strings))

        new_str = ''
        new_str_create_count = 0
        for i, encoded_string in enumerate(encoded_strings):

            decoded_string = decoded_strings.get(i)

            if (not decoded_string):
                # nothing to replace with
                continue

            value = decoded_string.get('value')
            encoding = decoded_string.get('encoding')

            if (not encoding or not value):
                # nothing to replace with
                continue

            try:
                # Some non-ascii characters were causing decoding issue with
                # the UnicodeDammit and working correctly with the decode function.
                # keeping previous logic in the except block incase of failure.
                if value:
                    value = value.decode(encoding)
                    new_str += value
                    new_str_create_count += 1
            except Exception:
                try:
                    if encoding != 'utf-8':
                        value = str(value, encoding)
                except Exception:
                    pass
                try:
                    # commenting the existing approach due to a new approach being deployed below
                    # substitute the encoded string with the decoded one
                    # input_str = input_str.replace(encoded_string, value)

                    # make new string instead of replacing in the input string because issue find in PAPP-9531
                    if value:
                        # value = UnicodeDammit(value).unicode_markup
                        new_str += UnicodeDammit(value).unicode_markup
                        new_str_create_count += 1
                except Exception:
                    pass

        # replace input string with new string because issue find in PAPP-9531
        if new_str and new_str_create_count == len(encoded_strings):
            self.debug_print("Creating a new string entirely from the encoded_strings and assigning into input_str")
            input_str = new_str

        return input_str

    def _get_email_headers_from_mail(self, mail, charset=None, email_headers=None):

        if mail:
            email_headers = list(mail.items())  # it's gives message headers

            # TODO: the next 2 ifs can be condensed to use 'or'
            if (charset is None):
                charset = mail.get_content_charset()

        if (not charset):
            charset = 'utf-8'

        if (not email_headers):
            return {}

        # Convert the header tuple into a dictionary
        headers = CaseInsensitiveDict()
        try:
            [headers.update({x[0]: self._get_string(x[1], charset)}) for x in email_headers]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while converting the header tuple into a dictionary"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        # Decode unicode subject
        # if '?UTF-8?' in headers['Subject']:
        #     chars = 'utf-8'
        #     headers['Subject'] = self._decode_subject(headers['Subject'], chars)

        # Handle received seperately
        try:
            received_headers = list()
            received_headers = [self._get_string(x[1], charset) for x in email_headers if x[0].lower() == 'received']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while handling the received header tuple separately"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        if (received_headers):
            headers['Received'] = received_headers

        # handle the subject string, if required add a new key
        subject = headers.get('Subject')
        if (subject):
            if (type(subject) == str):
                headers['decodedSubject'] = self._decode_uni_string(subject, subject)

        return headers

    def _get_mail_header_dict(self, email_data, action_result):

        try:
            mail = email.message_from_string(email_data)
        except Exception:
            return RetVal2(action_result.set_status(phantom.APP_ERROR, "Unable to create email object from data. Does not seem to be valid email"), None)

        headers = mail.__dict__.get('_headers')

        if (not headers):
            return RetVal2(action_result.set_status(phantom.APP_ERROR, "Could not extract header info from email object data. Does not seem to be valid email"), None)

        ret_val = {}
        for header in headers:
            ret_val[header[0]] = header[1]

        return RetVal2(phantom.APP_SUCCESS, ret_val)

    def _handle_email_with_container_id(self, action_result, container_id):

        ret_val, email_data, email_id = self._get_email_data_from_container(container_id, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status(), None

        action_result.update_summary({"email_id": email_id})

        ret_val, header_dict = self._get_mail_header_dict(email_data, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status(), None

        action_result.add_data(header_dict)

        return phantom.APP_SUCCESS, email_id

    def _handle_email_with_vault_id(self, action_result, vault_id, ingest_email, target_container_id=None, charset=None, user=None):

        ret_val, mail = self._get_email_data_from_vault(vault_id, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status(), None

        try:
            if mail:
                headers = self._get_email_headers_from_mail(mail, charset)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Unable to get email header string from message. {0}".format(error_text)), None

        if (not headers):
            return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the headers information from the provided MSG file"), None

        action_result.add_data(dict(headers))

        if not ingest_email:
            return phantom.APP_SUCCESS, None

        int_msg_id = headers.get("Message-ID")

        if not int_msg_id:
            return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the message_id information from the provided MSG file"), None

        params = {
            "int_msg_id": str(int_msg_id)
        }
        ret_val, item_matched = self._process_query(action_result, params, flag=True)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status(), None

        if not item_matched:
            err_msg = "Unable to ingest the message from the provided MSG file, the MSG file should be associated with the logged in SMTP user to ingest message from vault item."
            return action_result.set_status(phantom.APP_ERROR, err_msg), None

        item = item_matched[0]
        message_id = item.get("t_ItemId", {}).get("@Id")

        return phantom.APP_SUCCESS, message_id

    def _handle_email_with_message_id(self, action_result, email_id):

        try:
            data = ews_soap.xml_get_emails_data([email_id])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the ID. {0}".format(error_text)), None

        action_result.update_summary({"email_id": email_id})

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            message = "Error while getting email data for id {0}. Error: {1}".format(email_id, action_result.get_message())
            self.debug_print(message)
            self.send_progress(message)
            return action_result.set_status(phantom.APP_ERROR, message), None

        self._cleanse_key_names(resp_json)

        """
        ret_val, rfc822_format = self._get_rfc822_format(resp_json, action_result)
        if (phantom.is_fail(ret_val)):
            return phantom.APP_ERROR

        if (not rfc822_format):
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain rfc822 data')
        """

        message = resp_json.get('m_Items', {}).get('t_Message', {})

        # Remove mime content because it can be very large
        if 't_MimeContent' in message:
            message.pop('t_MimeContent')

        action_result.add_data(message)

        recipients_mailbox = message.get('t_ToRecipients', {}).get('t_Mailbox')

        if ((recipients_mailbox) and (type(recipients_mailbox) != list)):
            message['t_ToRecipients']['t_Mailbox'] = [recipients_mailbox]

        summary = {'subject': message.get('t_Subject'),
                'create_time': message.get('t_DateTimeCreated'),
                'sent_time': message.get('t_DateTimeSent')}

        action_result.update_summary(summary)

        return phantom.APP_SUCCESS, email_id

    def _get_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        message_id = param.get(EWSONPREM_JSON_ID)
        container_id = param.get(EWS_JSON_CONTAINER_ID)
        vault_id = param.get(EWS_JSON_VAULT_ID)
        self._target_user = param.get(EWSONPREM_JSON_EMAIL)
        use_current_container = param.get('use_current_container')
        target_container_id = None
        flag = False
        email_id = None

        if container_id is not None:
            ret_val, container_id = self._validate_integer(action_result, container_id, "container_id")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        if (use_current_container):
            target_container_id = self.get_container_id()

        ingest_email = param.get(EWSONPREM_JSON_INGEST_EMAIL, False)

        if (not message_id and not container_id and not vault_id):
            return action_result.set_status(phantom.APP_ERROR, "Please specify id, container_id or vault_id to get the email")

        if container_id or vault_id:

            if container_id:
                ret_val, email_id = self._handle_email_with_container_id(action_result, container_id)
                if (phantom.is_fail(ret_val)):
                    return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

                if (not ingest_email):
                    return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved an email for container ID")

            elif vault_id:
                ret_val, email_id = self._handle_email_with_vault_id(action_result, vault_id, ingest_email, target_container_id)
                if (phantom.is_fail(ret_val)):
                    return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

                if not ingest_email:
                    return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved an email for vault item")

        elif message_id:

            ret_val, email_id = self._handle_email_with_message_id(action_result, message_id)
            if (phantom.is_fail(ret_val)):
                return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

            if (not ingest_email):
                return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved an email for message ID")

        else:
            return action_result.set_status(phantom.APP_ERROR, "Please specify id, container_id or vault_id to get the email")

        # if the container_id or vault_id is given to fetch email and ingest_email is True, then,
        # while ingesting email to create artifacts of attachments, domains, hashes, ips and urls, flag has been set to True.

        # if message_id is given then artifacts has been created on the basis of asset configuration parameter while ingesting.
        if container_id or vault_id:
            flag = True

        if not email_id:
            return action_result.set_status(phantom.APP_ERROR, "Unable to get message ID from the given parameters")

        try:
            self._process_email_id(email_id, target_container_id, flag=flag)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Error occurred in _process_email_id with Message ID: {0}. {1}".format(email_id, error_text))
            action_result.update_summary({"container_id": None})
            return action_result.set_status(phantom.APP_ERROR, "Error processing email. {0}".format(error_text))

        if (target_container_id is None):
            # get the container id that of the email that was ingested
            container_id = self._get_container_id(email_id)
            action_result.update_summary({"container_id": container_id})
        else:
            action_result.update_summary({"container_id": target_container_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _valid_xml_char_ordinal(self, c):
        codepoint = ord(c)
        # conditions ordered by presumed frequency
        return (0x20 <= codepoint <= 0xD7FF or codepoint in (0x9, 0xA, 0xD) or 0xE000 <= codepoint <= 0xFFFD or 0x10000 <= codepoint <= 0x10FFFF)

    def _update_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        email_id = param[EWSONPREM_JSON_ID]
        self._target_user = param.get(EWSONPREM_JSON_EMAIL)
        category = param.get('category')
        subject = param.get('subject')

        if ((subject is None) and (category is None)):
            return action_result.set_status(phantom.APP_ERROR, "Please specify one of the email properties to update")

        # do a get on the message to get the change id
        try:
            data = ews_soap.xml_get_emails_data([email_id])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the ID. {0}".format(error_text))

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            message = "Error while getting email data for id {0}. Error: {1}".format(email_id, action_result.get_message())
            self.debug_print(message)
            self.send_progress(message)
            return phantom.APP_ERROR

        try:
            change_key = resp_json['m:Items']['t:Message']['t:ItemId']['@ChangeKey']
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Unable to get the change key of the email to update")

        if (category is not None):
            category = [x.strip() for x in category.split(',')]

        try:
            data = ews_soap.get_update_email(email_id, change_key, category, subject)
        except ValueError as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Validation failed for the given input parameter. {0}".format(error_text))

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_update_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (not resp_json):
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')
        try:
            data = ews_soap.xml_get_emails_data([email_id])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the ID. Error: {}".format(error_text))

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self._cleanse_key_names(resp_json)

        message = resp_json.get('m_Items', {}).get('t_Message', {})

        categories = message.get('t_Categories', {}).get('t_String')
        if (categories):
            if (type(categories) != list):
                categories = [categories]
            message['t_Categories'] = categories

        action_result.add_data(message)

        recipients_mailbox = message.get('t_ToRecipients', {}).get('t_Mailbox')

        if ((recipients_mailbox) and (type(recipients_mailbox) != list)):
            message['t_ToRecipients']['t_Mailbox'] = [recipients_mailbox]

        summary = {'subject': message.get('t_Subject'),
                'create_time': message.get('t_DateTimeCreated'),
                'sent_time': message.get('t_DateTimeSent')}

        action_result.update_summary(summary)

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _delete_email(self, param):

        action_result = ActionResult(dict(param))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        message_id = param[EWSONPREM_JSON_ID]
        self._target_user = param.get(EWSONPREM_JSON_EMAIL)

        message_ids = ph_utils.get_list_from_string(message_id)

        try:
            data = ews_soap.get_delete_email(message_ids)
        except Exception as e:
            self.add_action_result(action_result)
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, 'Parameter validation failed for the ID. {0}'.format(error_text))

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_delete_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            self.add_action_result(action_result)
            return action_result.get_status()

        if (not resp_json):
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        if (type(resp_json) != list):
            resp_json = [resp_json]

        for msg_id, resp_message in zip(message_ids, resp_json):

            curr_param = dict(param)
            curr_param.update({"id": msg_id})
            curr_ar = self.add_action_result(ActionResult(curr_param))

            resp_class = resp_message.get('@ResponseClass', '')

            if (resp_class == 'Error'):
                curr_ar.set_status(phantom.APP_ERROR, EWSONPREM_ERR_FROM_SERVER.format(**(self._get_error_details(resp_message))))
                continue
            curr_ar.set_status(phantom.APP_SUCCESS, "Email deleted successfully")

        # Set the Status
        return phantom.APP_SUCCESS

    def _clean_str(self, string):

        if (not string):
            return ''

        return string.replace('{', '-').replace('}', '-')

    def _extract_folder_path(self, extended_property):

        if (not extended_property):
            return ''

        # As of right now, the folder path is the only extended property
        # that the app extracts, so parse the value directly, once the app starts
        # parsing other extended properties, the 't:ExtendedFieldURI dictionary will
        # require to be parsed and validated
        value = extended_property.get('t:Value')

        if (not value):
            return ''

        value = value.lstrip('\\')

        # I don't know why exchange gives back the path with
        # '\\' separators since '\' is a valid char allowed in a folder name
        # makes things confusing and extra parsing code to be written.
        # Therefore the app treats folder paths with '/' as the separator, keeps
        # things less confusing for users.
        # value = value.replace('\\', '/')

        if (not value):
            return ''

        try:
            str(value)
        except UnicodeEncodeError:
            return UnicodeDammit(value).unicode_markup

        return value

    def _get_root_folder_id(self, action_result, is_public_folder=False):

        if is_public_folder:
            root_folder_id = 'publicfoldersroot'
        else:
            root_folder_id = 'root'

        folder_info = {'id': root_folder_id, 'display_name': root_folder_id, 'children_count': -1, 'folder_path': ''}

        return (phantom.APP_SUCCESS, folder_info)

    def _get_matching_folder_path(self, folder_list, folder_name, folder_path, action_result):
        """ The input folder is a list, meaning the folder name matched multiple folder
            Given the folder path, this function will return the one that matches, or fail
        """

        if (not folder_list):
            return (action_result(phantom.APP_ERROR,
                        "Unable to find info about folder '{0}'. Returned info list empty".format(folder_name)), None)

        for curr_folder in folder_list:
            curr_folder_path = self._extract_folder_path(curr_folder.get('t:ExtendedProperty'))

            if (UnicodeDammit(curr_folder_path).unicode_markup == UnicodeDammit(folder_path).unicode_markup):
                return (phantom.APP_SUCCESS, curr_folder)

        return (action_result.set_status(phantom.APP_ERROR,
                    "Folder paths did not match while searching for folder: '{0}'".format(folder_path)), None)

    def _get_folder_info(self, user, folder_path, action_result, is_public_folder=False):
        # hindsight is always 20-20, set the folder path separator to be '/', thinking folder names allow '\' as a char.
        # turns out even '/' is supported by office365, so let the action escape the '/' char if it's part of the folder name
        folder_path = folder_path.replace('\\/', self.REPLACE_CONST)
        folder_names = folder_path.split('/')

        folder_names = list(filter(None, folder_names))
        if not folder_names:
            return (action_result.set_status(phantom.APP_ERROR, "Please provide a valid value for folder path"), None)

        for i, folder_name in enumerate(folder_names):
            folder_names[i] = folder_name.replace(self.REPLACE_CONST, '/')

        if is_public_folder:
            parent_folder_id = 'publicfoldersroot'
        else:
            parent_folder_id = 'root'

        for i, folder_name in enumerate(folder_names):

            curr_valid_folder_path = '\\'.join(folder_names[:i + 1])

            self.save_progress('Getting info about {0}\\{1}'.format(self._clean_str(user), curr_valid_folder_path))

            input_xml = ews_soap.xml_get_children_info(user, child_folder_name=folder_name, parent_folder_id=parent_folder_id)

            ret_val, resp_json = self._make_rest_call(action_result, input_xml, self._check_findfolder_response)

            if (phantom.is_fail(ret_val)):
                return (ret_val, None)

            total_items = resp_json.get('m:RootFolder', {}).get('@TotalItemsInView', '0')

            if (total_items == '0'):
                return (action_result.set_status(phantom.APP_ERROR,
                            "Folder '{0}' not found, possibly not present".format(curr_valid_folder_path)), None)

            folder = resp_json.get('m:RootFolder', {}).get('t:Folders', {}).get('t:Folder')

            if (not folder):
                return (action_result.set_status(phantom.APP_ERROR,
                            "Information about '{0}' not found in response, possibly not present".format(curr_valid_folder_path)), None)

            if (type(folder) != list):
                folder = [folder]

            ret_val, folder = self._get_matching_folder_path(folder, folder_name, curr_valid_folder_path, action_result)

            if (phantom.is_fail(ret_val)):
                return (ret_val, None)

            if (not folder):
                return (action_result.set_status(phantom.APP_ERROR,
                    "Information for folder '{0}' not found in response, possibly not present".format(curr_valid_folder_path)), None)

            folder_id = folder.get('t:FolderId', {}).get('@Id')

            if (not folder_id):
                return (action_result.set_status(phantom.APP_ERROR,
                    "Folder ID information not found in response for '{0}', possibly not present".format(
                        curr_valid_folder_path)), None)

            parent_folder_id = folder_id
            folder_info = {'id': folder_id,
                    'display_name': folder.get('t:DisplayName'),
                    'children_count': folder.get('t:ChildFolderCount'),
                    'folder_path': self._extract_folder_path(folder.get('t:ExtendedProperty'))}

        return (phantom.APP_SUCCESS, folder_info)

    def _mark_as_junk(self, param, action):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        message_id = param[EWSONPREM_JSON_ID]

        move_email = param.get('move_to_junk_folder', param.get('move_from_junk_folder', False))

        is_junk = True if action == 'block' else False

        if EWSONPREM_JSON_EMAIL in param:
            self._target_user = param[EWSONPREM_JSON_EMAIL]

        message = "Sender blocked" if action == "block" else "Sender unblocked"

        try:
            data = ews_soap.xml_get_mark_as_junk(message_id, is_junk=is_junk, move_item=move_email)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the ID. Error: {}".format(str(e)))

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_markasjunk_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (move_email):
            try:
                new_email_id = resp_json['m:MovedItemId']['@Id']
            except Exception:
                return action_result.set_status(phantom.APP_SUCCESS, "Unable to get moved Email ID")

            action_result.add_data({'new_email_id': new_email_id})
            action_result.update_summary({'new_email_id': new_email_id})

            if (new_email_id != message_id):
                # Looks like the email was actually moved
                message += ". Message moved to Junk Folder" if action == "block" else ". Message moved out of Junk Folder"

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _copy_move_email(self, param, action="copy"):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        message_id = param[EWSONPREM_JSON_ID]

        folder_path = param[EWSONPREM_JSON_FOLDER]
        user = param[EWSONPREM_JSON_EMAIL]
        is_public_folder = param.get(EWS_JSON_IS_PUBLIC_FOLDER, False)

        # Set the user to impersonate (i.e. target_user), by default it is the destination user
        self._target_user = user

        # finally see if impersonation has been enabled/disabled for this action
        # as of right now copy or move email is the only action that allows over-ride
        impersonate = not(param.get(EWS_JSON_DONT_IMPERSONATE, False))

        # Use a different email if specified
        impersonate_email = param.get(EWS_JSON_IMPERSONATE_EMAIL)

        if (impersonate_email):
            self._target_user = impersonate_email

        self._impersonate = impersonate

        ret_val, folder_info = self._get_folder_info(user, folder_path, action_result, is_public_folder)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        try:
            data = ews_soap.get_copy_email(message_id, folder_info['id'])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, 'Parameter validation failed for the ID. {0}'.format(error_text))
        response_checker = self._check_copy_response

        if (action == "move"):
            try:
                data = ews_soap.get_move_email(message_id, folder_info['id'])
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
                return action_result.set_status(phantom.APP_ERROR, 'Parameter validation failed for the ID. {0}'.format(error_text))
            response_checker = self._check_move_response

        ret_val, resp_json = self._make_rest_call(action_result, data, response_checker)

        # Process errors
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (not resp_json):
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        new_email_id = None

        action_verb = 'copied' if (action == "copy") else 'moved'

        try:
            new_email_id = resp_json['m:Items']['t:Message']['t:ItemId']['@Id']
        except Exception:
            return action_result.set_status(phantom.APP_SUCCESS, "Email {0} successfully, but its message ID could not be retrieved".format(action_verb))

        action_result.add_data({'new_email_id': new_email_id})

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS, "Email {0} successfully".format(action_verb))

    def _resolve_name(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        email = param[EWSONPREM_JSON_EMAIL]

        self._impersonate = False

        data = ews_soap.xml_get_resolve_names(email)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_resolve_names_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if ( 'ErrorNameResolutionNoResults' in message):
                message = 'No email found. The input parameter might not be a valid alias or email.'

            return action_result.set_status(phantom.APP_ERROR, message)

        if (not resp_json):
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        resolution_set = resp_json.get('m:ResolutionSet', {}).get('t:Resolution')

        if (not resolution_set):
            return action_result.set_summary({'total_entries': 0})

        if (type(resolution_set) != list):
            resolution_set = [resolution_set]

        action_result.update_summary({'total_entries': len(resolution_set)})

        for curr_resolution in resolution_set:

            self._cleanse_key_names(curr_resolution)

            contact = curr_resolution.get('t_Contact')
            if (contact):
                email_addresses = contact.get('t_EmailAddresses', {}).get('t_Entry', [])
                if (email_addresses):
                    if (type(email_addresses) != list):
                        email_addresses = [email_addresses]
                    contact['t_EmailAddresses'] = email_addresses

            action_result.add_data(curr_resolution)

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _expand_dl(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        group = param[EWSONPREM_JSON_GROUP]

        self._impersonate = False

        data = ews_soap.get_expand_dl(group)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_expand_dl_response)

        # Process errors
        if (phantom.is_fail(ret_val)):

            message = action_result.get_message()
            if ('ErrorNameResolutionNoResults' in message):
                message += ' The input parameter might not be a distribution list.'
                action_result.add_data({"t_EmailAddress": group})
            return action_result.set_status(phantom.APP_ERROR, message)

        if (not resp_json):
            return action_result.set_status(phantom.APP_ERROR, 'Result does not contain RootFolder key')

        mailboxes = resp_json.get('m:DLExpansion', {}).get('t:Mailbox')

        if (not mailboxes):
            action_result.set_summary({'total_entries': 0})
            return action_result.set_status(phantom.APP_SUCCESS)

        if (type(mailboxes) != list):
            mailboxes = [mailboxes]

        action_result.update_summary({'total_entries': len(mailboxes)})

        for mailbox in mailboxes:
            if param.get('recursive', False) and "DL" in mailbox['t:MailboxType']:
                param[EWSONPREM_JSON_GROUP] = mailbox['t:EmailAddress']
                self._expand_dl(param)
            self._cleanse_key_names(mailbox)
            action_result.add_data(mailbox)

        # Set the Status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_email_epoch(self, resp_json):
        return None

    def _get_rfc822_format(self, resp_json, action_result):

        try:
            mime_content = resp_json['m:Items']['t:Message']['t:MimeContent']['#text']
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Email MimeContent missing in response.")

        try:
            rfc822_email = base64.b64decode(mime_content)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Unable to decode Email Mime Content. {0}".format(error_text))
            return action_result.set_status(phantom.APP_ERROR, "Unable to decode Email Mime Content")

        return (phantom.APP_SUCCESS, rfc822_email)

    def _get_attachment_meta_info(self, attachment, curr_key, parent_internet_message_id, parent_guid):

        attach_meta_info = dict()

        try:
            attach_meta_info['attachmentId'] = attachment['t:AttachmentId']['@Id']
        except Exception:
            pass

        try:
            attach_meta_info['attachmentType'] = curr_key[2:].replace('Attachment', '').lower()
        except Exception:
            pass

        attach_meta_info['parentInternetMessageId'] = parent_internet_message_id
        attach_meta_info['parentGuid'] = parent_guid

        # attachmentID, attachmentType
        for k, v in six.iteritems(attachment):

            if (not isinstance(v, str)):
                continue

            # convert the key to the convention used by cef
            cef_key_name = k[2:]
            cef_key_name = cef_key_name[0].lower() + cef_key_name[1:]
            attach_meta_info[cef_key_name] = v

        return attach_meta_info

    def _extract_ext_properties_from_attachments(self, resp_json):

        email_headers_ret = list()
        attach_meta_info_ret = list()

        if ('m:Items' not in resp_json):
            k = list(resp_json.keys())[0]
            resp_json['m:Items'] = resp_json.pop(k)

        # Get the attachments
        try:
            attachments = resp_json['m:Items']['t:Message']['t:Attachments']
        except Exception:
            return RetVal3(phantom.APP_SUCCESS)

        attachment_ids = list()

        internet_message_id = None
        try:
            internet_message_id = resp_json['m:Items']['t:Message']['t:InternetMessageId']
        except Exception:
            internet_message_id = None

        email_guid = resp_json['emailGuid']

        for curr_key in list(attachments.keys()):

            attachment_data = attachments[curr_key]

            if (type(attachment_data) != list):
                attachment_data = [attachment_data]

            for curr_attachment in attachment_data:

                attachment_ids.append(curr_attachment['t:AttachmentId']['@Id'])
                # Add the info that we have right now
                curr_attach_meta_info = self._get_attachment_meta_info(curr_attachment, curr_key, internet_message_id, email_guid)
                if (curr_attach_meta_info):
                    attach_meta_info_ret.append(curr_attach_meta_info)

        if (not attachment_ids):
            return RetVal3(phantom.APP_SUCCESS)

        data = ews_soap.xml_get_attachments_data(attachment_ids)

        action_result = ActionResult()

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_get_attachment_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            return RetVal3(action_result.get_status())

        if (type(resp_json) != list):
            resp_json = [resp_json]

        for curr_attachment_data in resp_json:

            try:
                curr_attachment_data = curr_attachment_data['m:Attachments']
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
                self.debug_print("Could not parse the attachments response", error_text)
                continue

            curr_attachment_data['emailGuid'] = str(uuid.uuid4())
            ret_val, data = self._extract_ext_properties(curr_attachment_data, internet_message_id, email_guid)

            if (data):
                email_headers_ret.append(data)
                ret_val, email_headers_info, attach_meta_info = self._extract_ext_properties_from_attachments(curr_attachment_data)
                if (email_headers_info):
                    email_headers_ret.extend(email_headers_info)
                if (attach_meta_info):
                    attach_meta_info_ret.extend(attach_meta_info)
            else:
                # This is a file attachment, we most probably already have the info from the resp_json
                # But update it with the call to the xml_get_attachments_data(..) There might be more info
                # that has to be updated
                curr_attach_meta_info = self._get_attachment_meta_info(curr_attachment_data['m:Items'], 't:FileAttachment', internet_message_id, email_guid)
                if (curr_attach_meta_info):
                    # find the attachment in the list and update it
                    matched_meta_info = list([x for x in attach_meta_info_ret if x.get('attachmentId', 'foo1') == curr_attach_meta_info.get('attachmentId', 'foo2')])
                    if (matched_meta_info):
                        matched_meta_info[0].update(curr_attach_meta_info)

        return (phantom.APP_SUCCESS, email_headers_ret, attach_meta_info_ret)

    def _extract_email_headers(self, email_headers):

        header_parser = HeaderParser()

        try:
            email_part = header_parser.parsestr(email_headers)
        except UnicodeEncodeError:
            email_part = header_parser.parsestr(UnicodeDammit(email_headers).unicode_markup)

        email_headers = list(email_part.items())

        headers = {}
        charset = 'utf-8'

        try:
            [headers.update({x[0]: self._get_string(x[1], charset)}) for x in email_headers]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while converting the header tuple into a dictionary"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        # Handle received seperately
        try:
            received_headers = list()
            received_headers = [self._get_string(x[1], charset) for x in email_headers if x[0].lower() == 'received']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while handling the received header tuple separately"
            self.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        if (received_headers):
            headers['Received'] = received_headers

        return headers

    def _extract_ext_properties(self, resp_json, parent_internet_message_id=None, parent_guid=None):

        if ('m:Items' not in resp_json):
            k = list(resp_json.keys())[0]
            resp_json['m:Items'] = resp_json.pop(k)

        headers = dict()
        extended_properties = list()

        # Get the Extended Properties
        try:
            extended_properties = resp_json['m:Items']['t:Message']['t:ExtendedProperty']
        except Exception:
            pass

        if extended_properties:
            if (type(extended_properties) != list):
                extended_properties = [extended_properties]

            for curr_ext_property in extended_properties:

                property_tag = curr_ext_property.get('t:ExtendedFieldURI', {}).get('@PropertyTag')
                value = curr_ext_property.get('t:Value')

                if (not property_tag):
                    continue

                if (property_tag.lower() == ews_soap.EXTENDED_PROPERTY_HEADERS.lower()) or (property_tag.lower() == ews_soap.EXTENDED_PROPERTY_HEADERS_RESPONSE.lower()):
                    email_headers = self._extract_email_headers(value)
                    if (email_headers is not None):
                        headers.update(email_headers)
                        continue
                if (property_tag == ews_soap.EXTENDED_PROPERTY_BODY_TEXT):
                    headers.update({'bodyText': value})

        # now parse the body in the main resp_json
        try:
            body_text = resp_json['m:Items']['t:Message']['t:Body']['#text']
        except Exception:
            body_text = None

        try:
            body_type = resp_json['m:Items']['t:Message']['t:Body']['@BodyType']
        except Exception:
            body_type = None

        if (body_text is not None):
            if (body_type is not None):
                body_key = "body{0}".format(body_type.title().replace(' ', ''))
                headers.update({body_key: body_text})

        # In some cases the message id is not part of the headers, in this case
        # copy the message id from the envelope to the header
        headers_ci = CaseInsensitiveDict(headers)
        message_id = headers_ci.get('message-id')
        if (message_id is None):
            try:
                message_id = resp_json['m:Items']['t:Message']['t:InternetMessageId']
                headers['Message-ID'] = message_id
            except Exception:
                pass

        if (parent_internet_message_id is not None):
            headers['parentInternetMessageId'] = parent_internet_message_id

        if (parent_guid is not None):
            headers['parentGuid'] = parent_guid

        headers['emailGuid'] = resp_json['emailGuid']

        return (phantom.APP_SUCCESS, headers)

    def _parse_email(self, resp_json, email_id, target_container_id, flag=False):

        try:
            mime_content = resp_json['m:Items']['t:Message']['t:MimeContent']['#text']
        except Exception:
            return (phantom.APP_ERROR, "Email MimeContent missing in response.")

        try:
            rfc822_email = base64.b64decode(mime_content)
            rfc822_email = UnicodeDammit(rfc822_email).unicode_markup
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            self.debug_print("Unable to decode Email Mime Content. {0}".format(error_text))
            return (phantom.APP_ERROR, "Unable to decode Email Mime Content")

        epoch = self._get_email_epoch(resp_json)

        email_header_list = list()
        attach_meta_info_list = list()
        resp_json['emailGuid'] = str(uuid.uuid4())

        ret_val, data = self._extract_ext_properties(resp_json)

        if (data):
            email_header_list.append(data)

        ret_val, attach_email_headers, attach_meta_info = self._extract_ext_properties_from_attachments(resp_json)

        if (attach_email_headers):
            email_header_list.extend(attach_email_headers)

        if (attach_meta_info):
            attach_meta_info_list.extend(attach_meta_info)

        config = self.get_config()

        if flag:
            config.update({
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True })

        process_email = ProcessEmail()
        return process_email.process_email(self, rfc822_email, email_id, config, epoch, target_container_id, email_headers=email_header_list,
                attachments_data=attach_meta_info_list)

    def _process_email_id(self, email_id, target_container_id=None, flag=False):

        action_result = ActionResult()
        try:
            data = ews_soap.xml_get_emails_data([email_id])
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
            return action_result.set_status(phantom.APP_ERROR, "Parameter validation failed for the ID. {0}".format(error_text))

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_getitem_response)

        # Process errors
        if (phantom.is_fail(ret_val)):
            message = "Error while getting email data for id {0}. Error: {1}".format(email_id, action_result.get_message())
            self.debug_print(message)
            self.send_progress(message)
            return phantom.APP_ERROR

        ret_val, message = self._parse_email(resp_json, email_id, target_container_id, flag)

        if (phantom.is_fail(ret_val)):
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _get_email_infos_to_process(self, offset, max_emails, action_result, restriction=None):

        config = self.get_config()

        # get the user
        poll_user = config.get(EWS_JSON_POLL_USER, config[phantom.APP_JSON_USERNAME])

        if (not poll_user):
            return (action_result.set_status(phantom.APP_ERROR, "Polling User Email not specified, cannot continue"), None)

        self._target_user = poll_user

        folder_path = config.get(EWS_JSON_POLL_FOLDER, 'Inbox')

        is_public_folder = config.get(EWS_JSON_IS_PUBLIC_FOLDER, False)
        ret_val, folder_info = self._get_folder_info(poll_user, folder_path, action_result, is_public_folder)

        if (phantom.is_fail(ret_val)):
            return (ret_val, None)

        manner = config[EWS_JSON_INGEST_MANNER]
        folder_id = folder_info['id']

        order = "Ascending"
        if (manner == EWS_INGEST_LATEST_EMAILS):
            order = "Descending"

        data = ews_soap.xml_get_email_ids(poll_user, order=order, offset=offset, max_emails=max_emails, folder_id=folder_id, restriction=restriction)

        ret_val, resp_json = self._make_rest_call(action_result, data, self._check_find_response)

        # Process errors
        if (phantom.is_fail(ret_val)):

            # Dump error messages in the log
            self.debug_print(action_result.get_message())

            # return error
            return (ret_val, None)

        resp_json = resp_json.get('m:RootFolder')

        if (not resp_json):
            return (action_result.set_status(phantom.APP_ERROR, 'Result does not contain required RootFolder key'), None)

        items = resp_json.get('t:Items')

        if (items is None):
            self.debug_print("Items is None")
            return (action_result.set_status(phantom.APP_SUCCESS, 'Result does not contain items key. Possibly no emails in folder'), None)

        items = resp_json.get('t:Items', {}).get('t:Message', [])

        if (type(items) != list):
            items = [items]

        email_infos = [{'id': x['t:ItemId']['@Id'], 'last_modified_time': x['t:LastModifiedTime']} for x in items]

        return (phantom.APP_SUCCESS, email_infos)

    def _pprint_email_id(self, email_id):
        return "{0}.........{1}".format(email_id[:20], email_id[-20:])

    def _process_email_ids(self, email_ids, action_result):

        if (email_ids is None):
            return action_result.set_status(phantom.APP_ERROR, "Did not get access to email IDs")

        self.save_progress("Got {0} email{1}".format(len(email_ids), '' if (len(email_ids) == 1) else 's'))

        failed_emails_parsing_list = []
        for i, email_id in enumerate(email_ids):
            self.send_progress("Querying email # {0} with id: {1}".format(i + 1, self._pprint_email_id(email_id)))
            try:
                ret_val = self._process_email_id(email_id)
                if phantom.is_fail(ret_val):
                    failed_emails_parsing_list.append(email_id)
            except Exception as e:
                error_code, error_msg = self._get_error_message_from_exception(e)
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
                self.debug_print("Error occurred in _process_email_id # {0} with Message ID: {1}. {2}".format(i, email_id, error_text))

                failed_emails_parsing_list.append(email_id)

        if len(failed_emails_parsing_list) == len(email_ids):
            return action_result.set_status(phantom.APP_ERROR, "ErrorExp in _process_email_id for all the email IDs: {}".format(str(failed_emails_parsing_list)))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_now(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get the maximum number of emails that we can pull
        config = self.get_config()

        # Get the maximum number of emails that we can pull, same as container count
        try:
            max_emails = int(param[phantom.APP_JSON_CONTAINER_COUNT])
            if max_emails == 0 or (max_emails and (not str(max_emails).isdigit() or max_emails <= 0)):
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-zero positive integer value in 'container_count' parameter")
        except Exception:
            return self.set_status(phantom.APP_ERROR, "Invalid container count")

        self.save_progress("Will be ingesting all possible artifacts (ignoring max artifacts value) for POLL NOW")

        email_id = param.get(phantom.APP_JSON_CONTAINER_ID)
        email_ids = [email_id]

        # get the user
        poll_user = UnicodeDammit(config.get(EWS_JSON_POLL_USER, config[phantom.APP_JSON_USERNAME])).unicode_markup

        if (not poll_user):
            return (action_result.set_status(phantom.APP_ERROR, "Polling User Email not specified, cannot continue"), None)

        self._target_user = poll_user

        if (not email_id):

            self.save_progress("POLL NOW Getting {0} '{1}' email ids".format(max_emails, config[EWS_JSON_INGEST_MANNER]))

            ret_val, email_infos = self._get_email_infos_to_process(0, max_emails, action_result)

            if (phantom.is_fail(ret_val)) or email_infos is None:
                return action_result.get_status()

            if not email_infos:
                return action_result.set_status(phantom.APP_SUCCESS, "No emails found for the ingestion process")

            email_ids = [x['id'] for x in email_infos]
        else:
            self.save_progress("POLL NOW Getting the single email id")

        ret_val = self._process_email_ids(email_ids, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_restriction(self):

        config = self.get_config()

        emails_after_key = 'last_ingested_format' if (config[EWS_JSON_INGEST_MANNER] == EWS_INGEST_LATEST_EMAILS) else 'last_email_format'

        date_time_string = self._state.get(emails_after_key)

        if (not date_time_string):
            return None

        return ews_soap.xml_get_restriction(date_time_string)

    def _get_next_start_time(self, last_time):

        # get the time string passed into a datetime object
        last_time = datetime.strptime(last_time, DATETIME_FORMAT)

        # add a second to it
        last_time = last_time + timedelta(seconds=1)

        # format it
        return last_time.strftime(DATETIME_FORMAT)

    def _manage_data_duplication(self, email_infos, email_index, max_emails, total_ingested, limit):
        # Define current time to store as starting reference for the next run of scheduled | interval polling
        utc_now = datetime.utcnow()
        self._state['last_ingested_format'] = utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')
        self._state['last_email_format'] = email_infos[email_index]['last_modified_time']
        self.save_state(self._state)

        if max_emails:
            if email_index == 0 or self._less_data:
                return None, None
            total_ingested += max_emails - self._dup_data
            self._remaining = limit - total_ingested
            if total_ingested >= limit:
                return None, None
            next_cycle_repeat_data = 0
            last_modified_time = email_infos[email_index]['last_modified_time']
            for x in reversed(email_infos):
                if x["last_modified_time"] == last_modified_time:
                    next_cycle_repeat_data += 1
                else:
                    break

            max_emails = next_cycle_repeat_data + self._remaining
            return max_emails, total_ingested
        else:
            return None, None

    def _on_poll(self, param):

        # on poll action that is supposed to be scheduled
        if self.is_poll_now():
            self.debug_print("DEBUGGER: Starting polling now")
            return self._poll_now(param)

        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Fetch first_run_max_emails for asset configuration
        first_run_max_emails = config[EWS_JSON_FIRST_RUN_MAX_EMAILS]
        ret_val, first_run_max_emails = self._validate_integer(action_result, first_run_max_emails, "Maximum Emails to Poll First Time")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Fetch max_containers for asset configuration
        max_containers = config[EWS_JSON_POLL_MAX_CONTAINERS]
        ret_val, max_containers = self._validate_integer(action_result, max_containers, "Maximum Containers for Scheduled Polling")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # handle poll_now i.e. scheduled poll
        # Get the email ids that we will be querying for, different set for first run
        if (self._state.get('first_run', True)):
            # set the config to _not_ first run
            max_emails = first_run_max_emails
            self.save_progress("First time Ingestion detected.")
        else:
            max_emails = max_containers

        total_ingested = 0
        limit = max_emails
        while True:
            self._dup_data = 0
            restriction = self._get_restriction()

            ret_val, email_infos = self._get_email_infos_to_process(0, max_emails, action_result, restriction)

            if (phantom.is_fail(ret_val)) or email_infos is None:
                return action_result.get_status()

            if not email_infos:
                return action_result.set_status(phantom.APP_SUCCESS, "No emails found for the restriction: {}".format(str(restriction)))

            if len(email_infos) < max_emails:
                self._less_data = True

            # if the config is for latest emails, then the 0th is the latest in the list returned, else
            # The last email is the latest in the list returned
            email_index = 0 if (config[EWS_JSON_INGEST_MANNER] == EWS_INGEST_LATEST_EMAILS) else -1

            email_ids = [x['id'] for x in email_infos]
            ret_val = self._process_email_ids(email_ids, action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            max_emails, total_ingested = self._manage_data_duplication(email_infos, email_index, max_emails, total_ingested, limit)
            if not max_emails:
                break

        # Save the state file data only if the ingestion gets successfully completed
        if (self._state.get('first_run', True)):
            self._state['first_run'] = False

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions"""

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        # Initialize it to success
        ret_val = phantom.APP_SUCCESS

        # Bunch if if..elif to process actions
        if (action == self.ACTION_ID_RUN_QUERY):
            ret_val = self._run_query_aqs(param)
        elif (action == self.ACTION_ID_DELETE_EMAIL):
            ret_val = self._delete_email(param)
        elif (action == self.ACTION_ID_UPDATE_EMAIL):
            ret_val = self._update_email(param)
        elif (action == self.ACTION_ID_GET_EMAIL):
            ret_val = self._get_email(param)
        elif (action == self.ACTION_ID_COPY_EMAIL):
            ret_val = self._copy_move_email(param)
        elif (action == self.ACTION_ID_MOVE_EMAIL):
            ret_val = self._copy_move_email(param, action='move')
        elif (action == self.ACTION_ID_BLOCK_SENDER):
            ret_val = self._mark_as_junk(param, action='block')
        elif (action == self.ACTION_ID_UNBLOCK_SENDER):
            ret_val = self._mark_as_junk(param, action='unblock')
        elif (action == self.ACTION_ID_EXPAND_DL):
            ret_val = self._expand_dl(param)
        elif (action == self.ACTION_ID_RESOLVE_NAME):
            ret_val = self._resolve_name(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()
    in_json = None
    in_email = None

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:

        in_json = f.read()
        in_json = json.loads(in_json)

        connector = EWSOnPremConnector()
        connector.print_progress_message = True

        data = in_json.get('data')
        raw_email = in_json.get('raw_email')

        # if neither present then treat it as a normal action test json
        if (not data and not raw_email):
            print(json.dumps(in_json, indent=4))

            if (session_id is not None):
                in_json['user_session_token'] = session_id
            result = connector._handle_action(json.dumps(in_json), None)
            print(result)
            exit(0)

        if (data):
            raw_email = data.get('raw_email')

        if (raw_email):
            config = {
                    "extract_attachments": True,
                    "extract_domains": True,
                    "extract_hashes": True,
                    "extract_ips": True,
                    "extract_urls": True,
                    "add_body_to_header_artifacts": True }

            process_email = ProcessEmail()
            ret_val, message = process_email.process_email(connector, raw_email, "manual_parsing", config, None)

    exit(0)
