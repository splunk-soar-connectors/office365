# File: ewsonprem_view.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
import re

import phantom.utils as ph_utils
from bs4 import BeautifulSoup


def _clean_email_text(email_text):
    if not email_text:
        return email_text

    email_text = re.sub("\r+", "\n", email_text)
    email_text = re.sub("\n{3,}", "\n\n", email_text)

    return email_text


def _process_data(data):
    email_body = data.get("t_Body", {}).get("#text")
    data["email_body"] = email_body

    if not email_body:
        return

    # try to load the email
    try:
        soup = BeautifulSoup(email_body, "html.parser")
        data["email_text"] = _clean_email_text(soup.get_text())
    except Exception:
        data["email_text"] = None

    recipients_mailbox = data.get("t_ToRecipients", {}).get("t_Mailbox")

    if recipients_mailbox:
        recipients_emails = [x.get("t_EmailAddress") for x in recipients_mailbox]
        data["recipients_emails"] = ", ".join(recipients_emails)

    return True


def _get_ctx_result_resolve_names(result):
    ctx_result = {}

    ctx_result["summary"] = result.get_summary()
    ctx_result["param"] = result.get_param()
    ctx_result["status"] = result.get_status()

    ctx_result["param"]["contains"] = "exchange alias"

    if ph_utils.is_email(ctx_result["param"]["email"]):
        ctx_result["param"]["contains"] = "email"

    message = result.get_message()

    # if status is failure then add the message
    if not ctx_result["status"]:
        ctx_result["message"] = message

    data = result.get_data()

    if not data:
        return ctx_result

    for curr_data in data:
        email_addresses = curr_data.get("t_Contact", {}).get("t_EmailAddresses", [])
        for curr_email in email_addresses:
            curr_email_text = curr_email.get("#text", "")
            curr_email["text"] = curr_email_text.split(":")[-1]

    ctx_result["data"] = data

    return ctx_result


def _get_ctx_result(result):
    ctx_result = {}

    ctx_result["summary"] = result.get_summary()
    ctx_result["param"] = result.get_param()
    ctx_result["status"] = result.get_status()

    message = result.get_message()

    # if status is failure then add the message
    if not ctx_result["status"]:
        ctx_result["message"] = message

    data = result.get_data()

    if not data:
        return ctx_result

    data = data[0]

    if data:
        _process_data(data)

    ctx_result["data"] = data

    return ctx_result


def display_email(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    # print context
    return "display_email.html"


def display_resolve_names(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result_resolve_names(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    # print(context)
    return "display_resolve_names.html"
