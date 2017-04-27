# --
# File: process_email.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

import email
import tempfile
from collections import OrderedDict
import os
import re
from bs4 import BeautifulSoup
import phantom.app as phantom
import phantom.utils as ph_utils
import mimetypes
import socket
from email.header import decode_header
from phantom.vault import Vault
import shutil
import hashlib
import json
import magic

# Any globals added here, should be initialized in the init() function
_base_connector = None
_config = dict()
_email_id_contains = list()
_container = dict()
_artifacts = list()
_attachments = list()

_container_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_artifact_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

FILE_EXTENSIONS = {
  '.vmsn': ['os memory dump', 'vm snapshot file'],
  '.vmss': ['os memory dump', 'vm suspend file'],
  '.js': ['javascript'],
  '.doc': ['doc'],
  '.docx': ['doc'],
  '.xls': ['xls'],
  '.xlsx': ['xls'],
}

MAGIC_FORMATS = [
  (re.compile('^PE.* Windows'), ['pe file', 'hash']),
  (re.compile('^MS-DOS executable'), ['pe file', 'hash']),
  (re.compile('^PDF '), ['pdf']),
  (re.compile('^MDMP crash'), ['process dump']),
  (re.compile('^Macromedia Flash'), ['flash']),
]

EWS_DEFAULT_ARTIFACT_COUNT = 100
EWS_DEFAULT_CONTAINER_COUNT = 100
HASH_FIXED_PHANTOM_VERSION = "2.0.201"

OFFICE365_APP_ID = "a73f6d32-c9d5-4fec-b024-43876700daa6"
EXCHANGE_ONPREM_APP_ID = "badc5252-4a82-4a6d-bc53-d1e503857124"
IMAP_APP_ID = "9f2e9f72-b0e5-45d6-92a7-09ef820476c1"

PROC_EMAIL_JSON_FILES = "files"
PROC_EMAIL_JSON_BODIES = "bodies"
PROC_EMAIL_JSON_DATE = "date"
PROC_EMAIL_JSON_FROM = "from"
PROC_EMAIL_JSON_SUBJECT = "subject"
PROC_EMAIL_JSON_TO = "to"
PROC_EMAIL_JSON_START_TIME = "start_time"
PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS = "extract_attachments"
PROC_EMAIL_JSON_EXTRACT_URLS = "extract_urls"
PROC_EMAIL_JSON_EXTRACT_IPS = "extract_ips"
PROC_EMAIL_JSON_EXTRACT_DOMAINS = "extract_domains"
PROC_EMAIL_JSON_EXTRACT_HASHES = "extract_hashes"
PROC_EMAIL_JSON_IPS = "ips"
PROC_EMAIL_JSON_HASHES = "hashes"
PROC_EMAIL_JSON_URLS = "urls"
PROC_EMAIL_JSON_DOMAINS = "domains"
PROC_EMAIL_JSON_MSG_ID = "message_id"
PROC_EMAIL_JSON_EMAIL_HEADERS = "email_headers"
PROC_EMAIL_CONTENT_TYPE_MESSAGE = "message/rfc822"

URI_REGEX = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
EMAIL_REGEX = r"\b[A-Z0-9._%+-]+@+[A-Z0-9.-]+\.[A-Z]{2,}\b"
EMAIL_REGEX2 = r'".*"@[A-Z0-9.-]+\.[A-Z]{2,}\b'
HASH_REGEX = r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
IPV6_REGEX = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))'
IPV6_REGEX += r'|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*'


uri_regexc = re.compile(URI_REGEX)
email_regexc = re.compile(EMAIL_REGEX, re.IGNORECASE)
email_regexc2 = re.compile(EMAIL_REGEX2, re.IGNORECASE)
hash_regexc = re.compile(HASH_REGEX)
ip_regexc = re.compile(IP_REGEX)
ipv6_regexc = re.compile(IPV6_REGEX)


def _get_file_contains(file_path):

    contains = []
    ext = os.path.splitext(file_path)[1]
    contains.extend(FILE_EXTENSIONS.get(ext, []))
    magic_str = magic.from_file(file_path)
    for regex, cur_contains in MAGIC_FORMATS:
        if regex.match(magic_str):
            contains.extend(cur_contains)

    return contains


def _is_ip(input_ip):

    if (ph_utils.is_ip(input_ip)):
        return True

    if (is_ipv6(input_ip)):
        return True

    return False


def is_ipv6(input_ip):

    try:
        socket.inet_pton(socket.AF_INET6, input_ip)
    except:  # not a valid v6 address
        return False

    return True


def _debug_print(*args):

    if (_base_connector) and (hasattr(_base_connector, 'debug_print')):
        _base_connector.debug_print(*args)

    return


def _clean_url(url):

    url = url.strip('>),.]\r\n')

    # Check before splicing, find returns -1 if not found
    # _and_ you will end up splicing on -1 (incorrectly)
    if ('<' in url):
        url = url[:url.find('<')]

    if ('>' in url):
        url = url[:url.find('>')]

    return url


def _extract_urls_domains(file_data, urls, domains):

    if ((not _config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]) and (not _config[PROC_EMAIL_JSON_EXTRACT_URLS])):
        return

    # try to load the email
    try:
        soup = BeautifulSoup(file_data, "html.parser")
    except Exception as e:
        _debug_print("Handled exception", e)
        return

    uris = []
    # get all tags that have hrefs
    links = soup.find_all(href=True)
    if (links):
        # it's html, so get all the urls
        uris = [x['href'] for x in links if (not x['href'].startswith('mailto:'))]
        # work on the text part of the link, they might be http links different from the href
        # and were either missed by the uri_regexc while parsing text or there was no text counterpart
        # in the email
        uri_text = [_clean_url(x.get_text()) for x in links]
        if (uri_text):
            uri_text = [x for x in uri_text if x.startswith('http')]
            if (uri_text):
                uris.extend(uri_text)
    else:
        # Parse it as a text file
        uris = re.findall(uri_regexc, file_data)
        if (uris):
            uris = [_clean_url(x) for x in uris]

    if (_config[PROC_EMAIL_JSON_EXTRACT_URLS]):
        # add the uris to the urls
        urls |= set(uris)

    if (_config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]):
        for uri in uris:
            domain = phantom.get_host_from_url(uri)
            if (domain) and (not _is_ip(domain)):
                domains.add(domain)
        # work on any mailto urls if present
        if (links):
            mailtos = [x['href'] for x in links if (x['href'].startswith('mailto:'))]
            for curr_email in mailtos:
                domain = curr_email[curr_email.find('@') + 1:]
                if (domain) and (not _is_ip(domain)):
                    domains.add(domain)

    return


def _get_ips(file_data, ips):

    # First extract what looks like an IP from the file, this is a faster operation
    ips_in_mail = re.findall(ip_regexc, file_data)
    ip6_in_mail = re.findall(ipv6_regexc, file_data)

    if (ip6_in_mail):
        for ip6_tuple in ip6_in_mail:
            ip6s = [x for x in ip6_tuple if x]
            ips_in_mail.extend(ip6s)

    # Now validate them
    if (ips_in_mail):
        ips_in_mail = set(ips_in_mail)
        # match it with a slower and difficult regex.
        # TODO: Fix this with a one step approach.
        ips_in_mail = [x for x in ips_in_mail if _is_ip(x)]
        if (ips_in_mail):
            ips |= set(ips_in_mail)


def _handle_body(body, parsed_mail, body_index, email_id):

    local_file_path = body['file_path']
    charset = body.get('charset')

    ips = parsed_mail[PROC_EMAIL_JSON_IPS]
    hashes = parsed_mail[PROC_EMAIL_JSON_HASHES]
    urls = parsed_mail[PROC_EMAIL_JSON_URLS]
    domains = parsed_mail[PROC_EMAIL_JSON_DOMAINS]

    file_data = None
    with open(local_file_path, 'r') as f:
        file_data = f.read()

    if ((file_data is None) or (len(file_data) == 0)):
        return phantom.APP_ERROR

    _parse_email_headers_as_inline(file_data, parsed_mail, charset, email_id)

    if (_config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]):
        emails = []
        emails.extend(re.findall(email_regexc, file_data))
        emails.extend(re.findall(email_regexc2, file_data))

        for curr_email in emails:
            domain = curr_email[curr_email.rfind('@') + 1:]
            if (domain) and (not ph_utils.is_ip(domain)):
                domains.add(domain)

    _extract_urls_domains(file_data, urls, domains)

    if (_config[PROC_EMAIL_JSON_EXTRACT_IPS]):
        _get_ips(file_data, ips)

    if (_config[PROC_EMAIL_JSON_EXTRACT_HASHES]):
        hashs_in_mail = re.findall(hash_regexc, file_data)
        if (hashs_in_mail):
            hashes |= set(hashs_in_mail)

    return phantom.APP_SUCCESS


def _add_artifacts(cef_key, input_set, artifact_name, start_index, artifacts):

    added_artifacts = 0
    for entry in input_set:

        # ignore empty entries
        if (not entry):
            continue

        artifact = {}
        artifact.update(_artifact_common)
        artifact['source_data_identifier'] = start_index + added_artifacts
        artifact['cef'] = {cef_key: entry}
        artifact['name'] = artifact_name
        _debug_print('Artifact:', artifact)
        artifacts.append(artifact)
        added_artifacts += 1

    return added_artifacts


def _parse_email_headers_as_inline(file_data, parsed_mail, charset, email_id):

    # remove the 'Forwarded Message' from the email text and parse it
    p = re.compile(r'.*Forwarded Message.*\r\n(.*)', re.IGNORECASE)
    email_text = p.sub(r'\1', file_data.strip())
    mail = email.message_from_string(email_text)

    # Get the array
    # email_headers = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

    _parse_email_headers(parsed_mail, mail, charset, add_email_id=email_id)

    # email_headers.append(mail.items())

    return phantom.APP_SUCCESS


def _add_email_header_artifacts(email_header_artifacts, start_index, artifacts):

    added_artifacts = 0
    for artifact in email_header_artifacts:

        artifact['source_data_identifier'] = start_index + added_artifacts
        artifacts.append(artifact)
        added_artifacts += 1

    return added_artifacts


def _create_artifacts(parsed_mail):

    # get all the artifact data in their own list objects
    ips = parsed_mail[PROC_EMAIL_JSON_IPS]
    hashes = parsed_mail[PROC_EMAIL_JSON_HASHES]
    urls = parsed_mail[PROC_EMAIL_JSON_URLS]
    domains = parsed_mail[PROC_EMAIL_JSON_DOMAINS]
    email_headers = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

    # set the default artifact dict

    artifact_id = 0

    # add artifacts
    added_artifacts = _add_artifacts('sourceAddress', ips, 'IP Artifact', artifact_id, _artifacts)
    artifact_id += added_artifacts

    added_artifacts = _add_artifacts('fileHash', hashes, 'Hash Artifact', artifact_id, _artifacts)
    artifact_id += added_artifacts

    added_artifacts = _add_artifacts('requestURL', urls, 'URL Artifact', artifact_id, _artifacts)
    artifact_id += added_artifacts

    # domains = [x.decode('idna') for x in domains]

    added_artifacts = _add_artifacts('destinationDnsDomain', domains, 'Domain Artifact', artifact_id, _artifacts)
    artifact_id += added_artifacts

    added_artifacts = _add_email_header_artifacts(email_headers, artifact_id, _artifacts)
    email_headers = email_headers
    artifact_id += added_artifacts

    return phantom.APP_SUCCESS


def _decode_uni_string(input_str, def_name):

    # try to find all the decoded strings, we could have multiple decoded strings
    # or a single decoded string between two normal strings separated by \r\n
    # YEAH...it could get that messy
    encoded_strings = re.findall(r'=\?.*?\?=', input_str, re.I)

    # return input_str as is, no need to do any conversion
    if (not encoded_strings):
        return input_str

    # get the decoded strings
    try:
        decoded_strings = [decode_header(x)[0] for x in encoded_strings]
        decoded_strings = [{'value': x[0], 'encoding': x[1]} for x in decoded_strings]
    except Exception as e:
        _debug_print("decoding: {0}".format(encoded_strings), e)
        return def_name

    # convert to dict for safe access, if it's an empty list, the dict will be empty
    decoded_strings = dict(enumerate(decoded_strings))

    for i, encoded_string in enumerate(encoded_strings):

        decoded_string = decoded_strings.get(i)

        if (not decoded_string):
            # notihing to replace with
            continue

        value = decoded_string.get('value')
        encoding = decoded_string.get('encoding')

        if (not encoding or not value):
            # notihing to replace with
            continue

        if (encoding != 'utf-8'):
            value = unicode(value, encoding).encode('utf-8')

        # substitute the encoded string with the decoded one
        input_str = input_str.replace(encoded_string, value)

    return input_str


def _get_container_name(parsed_mail, email_id):

    # Create the default name
    def_cont_name = "Email ID: {0}".format(email_id)

    # get the subject from the parsed mail
    subject = parsed_mail.get(PROC_EMAIL_JSON_SUBJECT)

    # if no subject then return the default
    if (not subject):
       return def_cont_name

    return _decode_uni_string(subject, def_cont_name)


def _handle_if_body(content_disp, content_id, content_type, part, bodies, file_path):

    process_as_body = False

    # if content disposition is None then assume that it is
    if (content_disp is None):
        process_as_body = True
    # if content disposition is inline
    elif (content_disp.lower().strip() == 'inline'):
        if ('text/html' in content_type) or ('text/plain' in content_type):
            process_as_body = True

    if (not process_as_body):
        return (phantom.APP_SUCCESS, True)

    part_payload = part.get_payload(decode=True)

    if (not part_payload):
        return (phantom.APP_SUCCESS, False)

    with open(file_path, 'wb') as f:
        f.write(part_payload)

    bodies.append({'file_path': file_path, 'charset': part.get_content_charset()})

    return (phantom.APP_SUCCESS, False)


def _handle_part(part, part_index, tmp_dir, extract_attach, parsed_mail):

    bodies = parsed_mail[PROC_EMAIL_JSON_BODIES]
    files = parsed_mail[PROC_EMAIL_JSON_FILES]

    # get the file_name
    file_name = part.get_filename()
    content_disp = part.get('Content-Disposition')
    content_type = part.get('Content-Type')
    content_id = part.get('Content-ID')

    if (file_name is None):
        # init name and extension to default values
        name = "part_{0}".format(part_index)
        extension = ".{0}".format(part_index)

        # Try to create an extension from the content type if possible
        if (content_type is not None):
            extension = mimetypes.guess_extension(re.sub(';.*', '', content_type))

        # Try to create a name from the content id if possible
        if (content_id is not None):
            name = content_id

        file_name = "{0}{1}".format(name, extension)
    else:
        file_name = _decode_uni_string(file_name, file_name)

    # Remove any chars that we don't want in the name
    file_path = "{0}/{1}_{2}".format(tmp_dir, part_index,
            file_name.translate(None, ''.join(['<', '>', ' '])))

    _debug_print("file_path: {0}".format(file_path))

    # is the part representing the body of the email
    status, process_further = _handle_if_body(content_disp, content_id, content_type, part, bodies, file_path)

    if (not process_further):
        return phantom.APP_SUCCESS

    # is this another email as an attachment
    if ((content_type is not None) and (content_type.find(PROC_EMAIL_CONTENT_TYPE_MESSAGE) != -1)):
        return phantom.APP_SUCCESS

    # This is an attachment, first check if it is another email or not
    if (extract_attach):
        part_payload = part.get_payload(decode=True)
        if (not part_payload):
            return phantom.APP_SUCCESS
        with open(file_path, 'wb') as f:
            f.write(part_payload)
        files.append({'file_name': file_name, 'file_path': file_path})

    return phantom.APP_SUCCESS


def _parse_email_headers(parsed_mail, part, charset=None, add_email_id=None):

    global _email_id_contains

    email_header_artifacts = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

    email_headers = part.items()

    if (charset is None):
        charset = part.get_content_charset()

    if (charset is None):
        charset = 'utf8'

    if (not email_headers):
        return 0

    # Convert the header tuple into adictionary
    headers = {}
    [headers.update({x[0]: unicode(x[1], charset)}) for x in email_headers]

    # Handle received seperately
    received_headers = [unicode(x[1], charset) for x in email_headers if x[0].lower() == 'received']

    if (received_headers):
        headers['Received'] = received_headers

    # Parse email keys first
    cef_artifact = {}
    cef_types = {}

    if (headers.get('From')):
        emails = headers['From']
        if (emails):
            cef_artifact.update({'fromEmail': emails})

    if (headers.get('To')):
        emails = headers['To']
        if (emails):
            cef_artifact.update({'toEmail': emails})

    # if the header did not contain any email addresses then ignore this artifact
    if (not cef_artifact):
        return 0

    cef_types.update({'fromEmail': ['email'], 'toEmail': ['email']})

    if (headers):
        cef_artifact['emailHeaders'] = headers

    # Adding the email id as a cef artifact crashes the UI when trying to show the action dialog box
    # so not adding this right now. All the other code to process the emailId is there, but the refraining
    # from adding the emailId
    # add_email_id = False
    if (add_email_id):
        cef_artifact['emailId'] = add_email_id
        if (_email_id_contains):
            cef_types.update({'emailId': _email_id_contains})

    artifact = {}
    artifact.update(_artifact_common)
    artifact['name'] = 'Email Artifact'
    artifact['cef'] = cef_artifact
    artifact['cef_types'] = cef_types
    email_header_artifacts.append(artifact)

    return len(email_header_artifacts)


def _handle_mail_object(mail, email_id, rfc822_email, tmp_dir, start_time_epoch):

    parsed_mail = OrderedDict()

    # Create a tmp directory for this email, will extract all files here
    tmp_dir = tmp_dir
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    extract_attach = _config[PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS]

    charset = mail.get_content_charset()

    if (charset is None):
        charset = 'utf8'

    # Extract fields and place it in a dictionary
    parsed_mail[PROC_EMAIL_JSON_SUBJECT] = mail.get('Subject', '')
    parsed_mail[PROC_EMAIL_JSON_FROM] = mail.get('From', '')
    parsed_mail[PROC_EMAIL_JSON_TO] = mail.get('To', '')
    parsed_mail[PROC_EMAIL_JSON_DATE] = mail.get('Date', '')
    parsed_mail[PROC_EMAIL_JSON_MSG_ID] = mail.get('Message-ID', '')
    parsed_mail[PROC_EMAIL_JSON_FILES] = files = []
    parsed_mail[PROC_EMAIL_JSON_BODIES] = bodies = []
    parsed_mail[PROC_EMAIL_JSON_START_TIME] = start_time_epoch
    parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS] = []

    # parse the parts of the email
    if (mail.is_multipart()):
        for i, part in enumerate(mail.walk()):
            add_email_id = None
            if (i == 0):
                add_email_id = email_id

            _parse_email_headers(parsed_mail, part, add_email_id=add_email_id)

            # parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS].append(part.items())

            # _debug_print("part: {0}".format(part.__dict__))
            # _debug_print("part type", type(part))
            if (part.is_multipart()):
                continue
            try:
                ret_val = _handle_part(part, i, tmp_dir, extract_attach, parsed_mail)
            except Exception as e:
                _debug_print("ErrorExp in _handle_part # {0}".format(i), e)
                continue

            if (phantom.is_fail(ret_val)):
                continue

    else:
        _parse_email_headers(parsed_mail, mail, add_email_id=email_id)
        # parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS].append(mail.items())
        file_path = "{0}/part_1.text".format(tmp_dir)
        with open(file_path, 'wb') as f:
            f.write(mail.get_payload(decode=True))
        bodies.append({'file_path': file_path, 'charset': mail.get_content_charset()})

    # get the container name
    container_name = _get_container_name(parsed_mail, email_id)

    if (container_name is None):
        return phantom.APP_ERROR

    # Add the container
    # first save the container, to do that copy things from parsed_mail to a new object
    container = {}
    container_data = dict(parsed_mail)

    # delete the header info, we dont make it a part of the container json
    del(container_data[PROC_EMAIL_JSON_EMAIL_HEADERS])
    container.update(_container_common)
    _container['source_data_identifier'] = email_id
    _container['name'] = container_name
    _container['data'] = {'raw_email': rfc822_email}

    # Create the sets before handling the bodies If both the bodies add the same ip
    # only one artifact should be created
    parsed_mail[PROC_EMAIL_JSON_IPS] = set()
    parsed_mail[PROC_EMAIL_JSON_HASHES] = set()
    parsed_mail[PROC_EMAIL_JSON_URLS] = set()
    parsed_mail[PROC_EMAIL_JSON_DOMAINS] = set()

    # For bodies
    for i, body in enumerate(bodies):
        if (not body):
            continue

        try:
            _handle_body(body, parsed_mail, i, email_id)
        except Exception as e:
            _debug_print("ErrorExp in _handle_body # {0}: {1}".format(i, str(e)))
            continue

    # Files
    _attachments.extend(files)

    _create_artifacts(parsed_mail)

    return phantom.APP_SUCCESS


def _init():

    global _base_connector
    global _config
    global _container
    global _artifacts
    global _attachments
    global _email_id_contains

    _base_connector = None
    _email_id_contains = list()
    _config = None
    _container = dict()
    _artifacts = list()
    _attachments = list()


def _set_email_id_contains(email_id):

    global _base_connector
    global _email_id_contains

    if (not _base_connector):
        return

    email_id = str(email_id)

    if ((_base_connector.get_app_id() == EXCHANGE_ONPREM_APP_ID) and (email_id.endswith('='))):
        _email_id_contains = [ "exchange email id" ]
    elif ((_base_connector.get_app_id() == OFFICE365_APP_ID) and (email_id.endswith('='))):
        _email_id_contains = [ "office 365 email id" ]
    elif (_base_connector.get_app_id() == IMAP_APP_ID) and (email_id.isdigit()):
        _email_id_contains = [ "imap email id" ]
    elif (ph_utils.is_sha1(email_id)):
        _email_id_contains = [ "vault id" ]

    return


def _int_process_email(rfc822_email, email_id, start_time_epoch):

    global _base_connector
    global _config

    mail = email.message_from_string(rfc822_email)

    ret_val = phantom.APP_SUCCESS

    tmp_dir = tempfile.mkdtemp(prefix='ph_email')

    try:
        ret_val = _handle_mail_object(mail, email_id, rfc822_email, tmp_dir, start_time_epoch)
    except Exception as e:
        message = "ErrorExp in _handle_mail_object: {0}".format(e)
        _debug_print(message)
        return (phantom.APP_ERROR, message, [])

    results = [{'container': _container, 'artifacts': _artifacts, 'files': _attachments, 'temp_directory': tmp_dir}]

    return (ret_val, "Email Parsed", results)


def process_email(base_connector, rfc822_email, email_id, config, epoch):

    _init()

    global _base_connector
    global _config

    _base_connector = base_connector
    _config = config

    try:
        _set_email_id_contains(email_id)
    except:
        pass

    ret_val, message, results = _int_process_email(rfc822_email, email_id, epoch)

    if (not ret_val):
        return (phantom.APP_ERROR, message)

    _parse_results(results)

    return (phantom.APP_SUCCESS, "Email Processed")


def _parse_results(results):

    global _base_connector

    param = _base_connector.get_current_param()

    container_count = EWS_DEFAULT_CONTAINER_COUNT
    artifact_count = EWS_DEFAULT_ARTIFACT_COUNT

    if (param):
        container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, EWS_DEFAULT_CONTAINER_COUNT)
        artifact_count = param.get(phantom.APP_JSON_ARTIFACT_COUNT, EWS_DEFAULT_ARTIFACT_COUNT)

    results = results[:container_count]

    for result in results:

        container = result.get('container')

        if (not container):
            continue

        container.update(_container_common)
        try:
            (ret_val, message, container_id) = _base_connector.save_container(container)
        except Exception as e:
            _base_connector.debug_print("Handled Exception while saving container", e)
            continue

        _base_connector.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, message, container_id))

        if (phantom.is_fail(ret_val)):
            message = "Failed to add Container for id: {0}, error msg: {1}".format(container['source_data_identifier'], message)
            _base_connector.debug_print(message)
            continue

        if (not container_id):
            message = "save_container did not return a container_id"
            _base_connector.debug_print(message)
            continue

        files = result.get('files')

        vault_ids = list()

        vault_artifacts_added = 0

        for curr_file in files:
            ret_val, added_to_vault = _handle_file(curr_file, vault_ids, container_id, vault_artifacts_added)

            if (added_to_vault):
                vault_artifacts_added += 1

        artifacts = result.get('artifacts')
        if (not artifacts):
            continue

        if (not _base_connector.is_poll_now()):
            artifacts = artifacts[:artifact_count]

        len_artifacts = len(artifacts)

        for j, artifact in enumerate(artifacts):

            if (not artifact):
                continue

            # add the container id to the artifact
            artifact['container_id'] = container_id
            _set_sdi((j + vault_artifacts_added), artifact)

            # if it is the last artifact of the last container
            if ((j + 1) == len_artifacts):
                # mark it such that active playbooks get executed
                artifact['run_automation'] = True

            ret_val, status_string, artifact_id = _base_connector.save_artifact(artifact)
            _base_connector.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

    # delete any temp directories that were created by the email parsing function
    [shutil.rmtree(x['temp_directory'], ignore_errors=True) for x in results if x.get('temp_directory')]

    return _base_connector.set_status(phantom.APP_SUCCESS)


def _add_vault_hashes_to_dictionary(cef_artifact, vault_id):

    vault_info = Vault.get_file_info(vault_id=vault_id)

    if (not vault_info):
        return (phantom.APP_ERROR, "Vault ID not found")

    # The return value is a list, each item represents an item in the vault
    # matching the vault id, the info that we are looking for (the hashes)
    # will be the same for every entry, so just access the first one
    try:
        metadata = vault_info[0].get('metadata')
    except:
        return (phantom.APP_ERROR, "Failed to get vault item metadata")

    try:
        cef_artifact['fileHashSha256'] = metadata['sha256']
    except:
        pass

    try:
        cef_artifact['fileHashMd5'] = metadata['md5']
    except:
        pass

    try:
        cef_artifact['fileHashSha1'] = metadata['sha1']
    except:
        pass

    return (phantom.APP_SUCCESS, "Mapped hash values")


def _handle_file(curr_file, vault_ids, container_id, artifact_id):

    file_name = curr_file.get('file_name')

    local_file_path = curr_file['file_path']

    contains = _get_file_contains(local_file_path)

    # lets move the data into the vault
    vault_attach_dict = {}

    if (not file_name):
        file_name = os.path.basename(local_file_path)

    _base_connector.debug_print("Vault file name: {0}".format(file_name))

    vault_attach_dict[phantom.APP_JSON_ACTION_NAME] = _base_connector.get_action_name()
    vault_attach_dict[phantom.APP_JSON_APP_RUN_ID] = _base_connector.get_app_run_id()

    vault_ret = {}

    file_name = _decode_uni_string(file_name, file_name)

    try:
        vault_ret = Vault.add_attachment(local_file_path, container_id, file_name, vault_attach_dict)
    except Exception as e:
        _base_connector.debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(e))
        return (phantom.APP_ERROR, phantom.APP_ERROR)

    # _base_connector.debug_print("vault_ret_dict", vault_ret_dict)

    if (not vault_ret.get('succeeded')):
        _base_connector.debug_print("Failed to add file to Vault: {0}".format(json.dumps(vault_ret)))
        return (phantom.APP_ERROR, phantom.APP_ERROR)

    # add the vault id artifact to the container
    cef_artifact = {}
    if (file_name):
        cef_artifact.update({'fileName': file_name})

    if (phantom.APP_JSON_HASH in vault_ret):
        cef_artifact.update({'vaultId': vault_ret[phantom.APP_JSON_HASH],
            'cs6': vault_ret[phantom.APP_JSON_HASH],
            'cs6Label': 'Vault ID'})

        # now get the rest of the hashes and add them to the cef artifact
        _add_vault_hashes_to_dictionary(cef_artifact, vault_ret[phantom.APP_JSON_HASH])

    if (not cef_artifact):
        return (phantom.APP_SUCCESS, phantom.APP_ERROR)

    artifact = {}
    artifact.update(_artifact_common)
    artifact['container_id'] = container_id
    artifact['name'] = 'Vault Artifact'
    artifact['cef'] = cef_artifact
    if (contains):
        artifact['cef_types'] = {'vaultId': contains, 'cs6': contains}
    _set_sdi(artifact_id, artifact)

    ret_val, status_string, artifact_id = _base_connector.save_artifact(artifact)
    _base_connector.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

    return (phantom.APP_SUCCESS, ret_val)


def _set_sdi(default_id, input_dict):

    if ('source_data_identifier' in input_dict):
        del input_dict['source_data_identifier']
    dict_hash = None

    # first get the phantom version
    phantom_version = _base_connector.get_product_version()

    if (not phantom_version):
        dict_hash = _create_dict_hash(input_dict)
    else:
        ver_cmp = cmp(phantom_version, HASH_FIXED_PHANTOM_VERSION)

        if (ver_cmp == -1):
            dict_hash = _create_dict_hash(input_dict)

    if (dict_hash):
        input_dict['source_data_identifier'] = dict_hash
    else:
        # Remove this code once the backend has fixed PS-4216 _and_ it has been
        # merged into next so that 2.0 and 2.1 has the code
        input_dict['source_data_identifier'] = _create_dict_hash(input_dict)

    return phantom.APP_SUCCESS


def _create_dict_hash(input_dict):

    input_dict_str = None

    if (not input_dict):
        return None

    try:
        input_dict_str = json.dumps(input_dict, sort_keys=True)
    except Exception as e:
        _base_connector.debug_print('Handled exception in _create_dict_hash', e)
        return None

    return hashlib.md5(input_dict_str).hexdigest()
