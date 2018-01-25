# --
# File: ews_soap.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# http://lxml.de/tutorial.html
from lxml.builder import ElementMaker
from lxml import etree

# The name spaces
SOAP_ENVELOPE_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
MESSAGES_NAMESPACE = "http://schemas.microsoft.com/exchange/services/2006/messages"
TYPES_NAMESPACE = "http://schemas.microsoft.com/exchange/services/2006/types"

# namespace map
NSMAP = {"soap": SOAP_ENVELOPE_NAMESPACE, "m": MESSAGES_NAMESPACE, "t": TYPES_NAMESPACE}

# Elements used
S = ElementMaker(namespace=SOAP_ENVELOPE_NAMESPACE, nsmap=NSMAP)
M = ElementMaker(namespace=MESSAGES_NAMESPACE, nsmap=NSMAP)
T = ElementMaker(namespace=TYPES_NAMESPACE, nsmap=NSMAP)


def xml_get_restriction(greater_than_time=None, message_id=None):

    filters = []

    if (greater_than_time):
        greater_than_time = T.IsGreaterThan(
                T.FieldURI({'FieldURI': 'item:LastModifiedTime'}),
                T.FieldURIOrConstant(T.Constant({'Value': greater_than_time})))
        filters.append(greater_than_time)

    if (message_id):
            message_id = T.IsNotEqualTo(
                    T.FieldURI({'FieldURI': 'item:ItemId'}),
                    T.FieldURIOrConstant(T.Constant({'Value': message_id})))
            filters.append(message_id)

    if (not filters):
        return None

    if (len(filters) > 1):
        restriction = M.Restriction(T.And(*filters))
    else:
        restriction = M.Restriction(*filters)

    return restriction


def xml_get_email_ids(user, folder_id, order, offset, max_emails, restriction):

    elements = []

    additional_properties = T.AdditionalProperties(
            T.FieldURI({'FieldURI': 'item:LastModifiedTime'}))

    item_shape = M.ItemShape(
            T.BaseShape('IdOnly'),
            additional_properties)

    elements.append(item_shape)

    page = M.IndexedPageItemView(
            {'MaxEntriesReturned': str(max_emails)},
            {'Offset': str(offset)},
            {'BasePoint': 'Beginning'})

    elements.append(page)

    if (restriction):
        elements.append(restriction)

    sort_order = M.SortOrder(
            T.FieldOrder(
                {'Order': order},
                T.FieldURI({'FieldURI': 'item:LastModifiedTime'})))

    elements.append(sort_order)

    # Treat it as a 'inbox'
    parent_folder_ids = M.ParentFolderIds(
            T.DistinguishedFolderId(
                {'Id': folder_id},
                T.Mailbox(T.EmailAddress(user.decode('utf-8')))))

    if (folder_id != 'inbox'):
        parent_folder_ids = M.ParentFolderIds(T.FolderId({'Id': folder_id}))

    elements.append(parent_folder_ids)

    find_item = M.FindItem(
            {'Traversal': 'Shallow'},
            *elements)

    return find_item


def xml_get_resolve_names(email):
    """
    https://msdn.microsoft.com/en-us/library/office/aa563518(v=exchg.150).aspx
    """

    return M.ResolveNames({'ReturnFullContactData': "true"}, M.UnresolvedEntry(email.decode('utf-8')))


def get_expand_dl(email):
    """
    https://msdn.microsoft.com/en-us/library/office/aa494152(v=exchg.150).aspx
    """

    # All documenation says that Mailbox should be a 'T', but that just throws an error
    # it has to be an 'M' for things to work
    return M.ExpandDL(M.Mailbox(T.EmailAddress(email.decode('utf-8'))))


def xml_get_emails_data(email_ids):
    """
    https://msdn.microsoft.com/en-us/library/office/aa566013(v=exchg.150).aspx
    """

    additional_properties = T.AdditionalProperties(
            T.FieldURI({'FieldURI': 'item:Subject'}),
            T.FieldURI({'FieldURI': 'message:From'}),
            T.FieldURI({'FieldURI': 'message:Sender'}),
            T.FieldURI({'FieldURI': 'message:InternetMessageId'}),
            T.FieldURI({'FieldURI': 'item:DateTimeReceived'}),
            T.FieldURI({'FieldURI': 'item:LastModifiedTime'}),
            T.FieldURI({'FieldURI': 'item:Body'}))

    item_shape = M.ItemShape(
            T.BaseShape('Default'),
            T.IncludeMimeContent('true'),
            additional_properties)

    item_ids = M.ItemIds()
    [item_ids.append(T.ItemId({'Id': x})) for x in email_ids]

    get_item = M.GetItem(
            item_shape,
            item_ids)

    return get_item


def get_search_request_aqs(folder_ids, aqs, email_range="0-10"):

    elements = []

    # Item Shape
    additional_properties = T.AdditionalProperties(
            T.FieldURI({'FieldURI': 'item:Subject'}),
            T.FieldURI({'FieldURI': 'message:From'}),
            T.FieldURI({'FieldURI': 'message:Sender'}),
            T.FieldURI({'FieldURI': 'message:InternetMessageId'}),
            T.FieldURI({'FieldURI': 'item:DateTimeReceived'}),
            T.ExtendedFieldURI({'PropertySetId': 'aa3df801-4fc7-401f-bbc1-7c93d6498c2e', 'PropertyName': 'ItemIndex', 'PropertyType': 'Integer'}))

    item_shape = M.ItemShape(
            T.BaseShape('IdOnly'),
            additional_properties)
    elements.append(item_shape)

    # IndexedPageItemView
    mini, maxi = (int(x) for x in email_range.split('-'))

    page = M.IndexedPageItemView(
            {'MaxEntriesReturned': str(maxi - mini + 1)},
            {'Offset': str(mini)},
            {'BasePoint': 'Beginning'})
    elements.append(page)

    # sort order
    sort_order = M.SortOrder(
            T.FieldOrder(
                {'Order': 'Descending'},
                T.FieldURI({'FieldURI': 'item:DateTimeReceived'})))
    elements.append(sort_order)

    # parent folder ids
    t_folder_ids = [T.FolderId({'Id': x}) for x in folder_ids]

    parent_folder_ids = M.ParentFolderIds(*t_folder_ids)

    elements.append(parent_folder_ids)

    # query string
    query_string = M.QueryString(aqs.decode('utf-8'))
    elements.append(query_string)

    find_item = M.FindItem(
            {'Traversal': 'Shallow'},
            *elements)

    return find_item


def get_search_request_filter(folder_ids, subject=None, sender=None, body=None, int_msg_id=None, restriction=None, email_range="0-10"):
    """
    Link for Restriction node
    https://msdn.microsoft.com/en-us/library/office/aa563791(v=exchg.150).aspx

    Link for the FieldURI's
    https://msdn.microsoft.com/en-us/library/office/aa494315(v=exchg.150).aspx

    Link to article that explains how all this fits in
    https://msdn.microsoft.com/en-us/library/office/dn579422(v=exchg.150).aspx
    """

    elements = []

    # Item Shape
    additional_properties = T.AdditionalProperties(
            T.FieldURI({'FieldURI': 'item:Subject'}),
            T.FieldURI({'FieldURI': 'message:From'}),
            T.FieldURI({'FieldURI': 'message:Sender'}),
            T.FieldURI({'FieldURI': 'message:InternetMessageId'}),
            T.FieldURI({'FieldURI': 'item:DateTimeReceived'}),
            T.ExtendedFieldURI({'PropertySetId': 'aa3df801-4fc7-401f-bbc1-7c93d6498c2e', 'PropertyName': 'ItemIndex', 'PropertyType': 'Integer'}))

    item_shape = M.ItemShape(
            T.BaseShape('IdOnly'),
            additional_properties)
    elements.append(item_shape)

    # IndexedPageItemView
    mini, maxi = (int(x) for x in email_range.split('-'))

    page = M.IndexedPageItemView(
            {'MaxEntriesReturned': str(maxi - mini + 1)},
            {'Offset': str(mini)},
            {'BasePoint': 'Beginning'})
    elements.append(page)

    # Restriction
    if (restriction is None):
        filters = []

        if (subject):
            sub_filt = T.Contains(
                    {'ContainmentMode': 'Substring', 'ContainmentComparison': 'IgnoreCase'},
                    T.FieldURI({'FieldURI': 'item:Subject'}),
                    T.Constant({'Value': subject.decode('utf-8')}))
            filters.append(sub_filt)

        if (sender):
            sender_filter = T.IsEqualTo(
                    T.FieldURI({'FieldURI': 'message:Sender'}),
                    T.FieldURIOrConstant(
                        T.Constant({'Value': sender.decode('utf-8')})))
            filters.append(sender_filter)

        if (int_msg_id):
            sender_filter = T.IsEqualTo(
                    T.FieldURI({'FieldURI': 'message:InternetMessageId'}),
                    T.FieldURIOrConstant(
                        T.Constant({'Value': int_msg_id.decode('utf-8')})))
            filters.append(sender_filter)

        if (body):
            body_filter = T.Contains(
                    {'ContainmentMode': 'Substring', 'ContainmentComparison': 'IgnoreCase'},
                    T.FieldURI({'FieldURI': 'item:Body'}),
                    T.Constant({'Value': body.decode('utf-8')}))
            filters.append(body_filter)

        if (filters):
            if (len(filters) > 1):
                restriction = M.Restriction(T.And(*filters))
            else:
                restriction = M.Restriction(*filters)

    if (restriction is not None):
        elements.append(restriction)

    # sort order
    sort_order = M.SortOrder(
            T.FieldOrder(
                {'Order': 'Descending'},
                T.FieldURI({'FieldURI': 'item:DateTimeReceived'})))
    elements.append(sort_order)

    # parent folder ids
    t_folder_ids = [T.FolderId({'Id': x}) for x in folder_ids]

    parent_folder_ids = M.ParentFolderIds(*t_folder_ids)

    elements.append(parent_folder_ids)

    find_item = M.FindItem(
            {'Traversal': 'Shallow'},
            *elements)

    return find_item


def get_delete_email(message_ids):

    if (type(message_ids) != list):
        message_ids = [message_ids]

    item_ids = [T.ItemId({'Id': x}) for x in message_ids]
    item_ids_m = M.ItemIds(*item_ids)

    del_item = M.DeleteItem(
            {'DeleteType': 'HardDelete'},
            item_ids_m)

    return del_item


def get_copy_email(message_id, folder_id):

    return M.CopyItem(
            M.ToFolderId(
                T.FolderId({'Id': folder_id})),
            M.ItemIds(
                T.ItemId({'Id': message_id})))


def xml_get_root_folder_id(user):

    folder_shape = M.FolderShape(T.BaseShape('IdOnly'))
    folder_ids = M.FolderIds(T.DistinguishedFolderId({'Id': 'root'}, T.Mailbox(T.EmailAddress(user.decode('utf-8')))))

    return M.GetFolder(folder_shape, folder_ids)


def xml_get_children_info(user, child_folder_name=None, parent_folder_id='root'):

    folder_shape = M.FolderShape(
            T.BaseShape('IdOnly'),
            T.AdditionalProperties(
                T.FieldURI({'FieldURI': 'folder:FolderId'}),
                T.FieldURI({'FieldURI': 'folder:FolderClass'}),
                T.FieldURI({'FieldURI': 'folder:ChildFolderCount'}),
                T.FieldURI({'FieldURI': 'folder:ParentFolderId'}),
                T.ExtendedFieldURI({'PropertyTag': '26293', 'PropertyType': 'String'}),
                T.FieldURI({'FieldURI': 'folder:DisplayName'})))

    filters = []
    restriction = None
    """
    note_equal_to = T.IsEqualTo(
            T.FieldURI({'FieldURI': 'folder:FolderClass'}),
            T.FieldURIOrConstant(
                T.Constant({'Value': 'IPF.Note'})))
    filters.append(note_equal_to)
    """

    if (child_folder_name):
        display_name_equal_to = T.IsEqualTo(
                T.FieldURI({'FieldURI': 'folder:DisplayName'}),
                T.FieldURIOrConstant(
                    T.Constant({'Value': child_folder_name.decode('utf-8')})))
        filters.append(display_name_equal_to)

    if (filters):
        if (len(filters) > 1):
            restriction = M.Restriction(T.And(*filters))
        else:
            restriction = M.Restriction(*filters)

    if (user):
        if (parent_folder_id == 'root'):
            par_folder_id = M.ParentFolderIds(
                    T.DistinguishedFolderId(
                        {'Id': parent_folder_id},
                        T.Mailbox(T.EmailAddress(user.decode('utf-8')))))
        else:
            par_folder_id = M.ParentFolderIds(
                    T.FolderId({'Id': parent_folder_id}))
    else:
        par_folder_id = M.ParentFolderIds(T.DistinguishedFolderId({'Id': parent_folder_id}))

    if (restriction is not None):
        return M.FindFolder(
                {'Traversal': 'Deep'},
                folder_shape,
                restriction,
                par_folder_id)

    return M.FindFolder(
            {'Traversal': 'Deep'},
            folder_shape,
            par_folder_id)


def add_to_envelope(lxml_obj, target_user=None):

    header = S.Header(T.RequestServerVersion({'Version': 'Exchange2010'}))

    if (target_user):
        impersonation = T.ExchangeImpersonation(
                T.ConnectingSID(
                    T.SmtpAddress(target_user.decode('utf-8'))))
        header.append(impersonation)

    return S.Envelope(
            header,
            S.Body(lxml_obj))


def get_string(lxml_obj):
    return etree.tostring(lxml_obj, encoding='utf-8')
