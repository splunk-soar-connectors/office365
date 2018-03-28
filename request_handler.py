# --
# File: request_handler.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --
import os
import json
import requests
import encryption_helper

from django.http import HttpResponse


def handle_request(request, path_parts):
    return Office365RequestHandler(request, path_parts).handle_request()


def _get_dir_name_from_app_name(app_name):
    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if (not app_name):
        app_name = "app_for_phantom"
    return app_name


class Office365RequestHandler():
    def __init__(self, request, path_parts):
        self._request = request
        self._path_parts = path_parts

    def _return_error(self, error_msg, status):
        state = self._rsh.load_state()
        state['error'] = True
        self._rsh.save_state(state)
        return HttpResponse(error_msg, status=status)

    def _get_oauth_token(self, code):
        state = self._rsh.load_state()

        client_id = state['client_id']
        redirect_uri = state['redirect_url']
        request_url = state['request_url']

        body = {
            'grant_type': 'authorization_code',
            'resource': 'https://outlook.office365.com/',
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'code': code
        }

        try:
            r = requests.post(
                request_url + '/token',
                data=body
            )
            r.raise_for_status()
            resp_json = r.json()
        except Exception as e:
            return False, self._return_error(
                "Error retrieving OAuth Token: {}".format(str(e)),
                401
            )
        state['oauth_token'] = resp_json
        self._rsh.save_state(state)

        return (True, None)

    def handle_request(self):
        GET = self._request.GET
        asset_id = GET.get('state')
        self._rsh = RequestStateHandler(asset_id)
        error = GET.get('error')
        if error:
            error_msg = GET.get('error_description')
            return self._return_error(error_msg, 401)

        code = GET.get('code')

        ret_val, http_object = self._get_oauth_token(code)

        if (ret_val is False):
            return http_object

        return HttpResponse("You can now close this page")


class RequestStateHandler():
    def __init__(self, asset_id):
        self._asset_id = asset_id
        pass

    def _encrypt_state(self, state):
        if 'oauth_token' in state:
            oauth_token = state['oauth_token']
            state['oauth_token'] = encryption_helper.encrypt(  # pylint: disable=E1101
                json.dumps(oauth_token),
                self._asset_id
            )
        return state

    def _decrypt_state(self, state):
        if 'oauth_token' in state:
            oauth_token = encryption_helper.decrypt(  # pylint: disable=E1101
                state['oauth_token'],
                self._asset_id
            )
            state['oauth_token'] = json.loads(oauth_token)
        return state

    def _get_state_file(self):
        dirpath = os.path.split(__file__)[0]
        state_file = "{0}/{1}_state.json".format(dirpath, self._asset_id)
        return state_file

    def delete_state(self):
        state_file = self._get_state_file()
        try:
            os.remove(state_file)
        except:
            pass

        return True

    def save_state(self, state):
        state = self._encrypt_state(state)
        state_file = self._get_state_file()
        try:
            with open(state_file, 'w+') as fp:
                fp.write(json.dumps(state))
                fp.close()
        except:
            pass

        return True

    def load_state(self):
        state_file = self._get_state_file()
        state = {}
        try:
            with open(state_file, 'r') as fp:
                in_json = fp.read()
                state = json.loads(in_json)
                fp.close()
        except:
            pass

        state = self._decrypt_state(state)
        return state