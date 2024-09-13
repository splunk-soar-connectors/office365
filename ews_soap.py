# File: ews_soap.py
#
# Copyright (c) 2016-2024 Splunk Inc.
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
# http://lxml.de/tutorial.html
from bs4 import UnicodeDammit
from lxml import etree
from lxml.builder import ElementMaker

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

EXTENDED_PROPERTY_HEADERS = "0x007D"
EXTENDED_PROPERTY_HEADERS_RESPONSE = "0x7D"
EXTENDED_PROPERTY_BODY_TEXT = "0x1000"
EXTENDED_PROPERTY_BODY_HTML = "0x1013"


# WARNING: pylint is disabled for the whole file due to ElementMaker
# pylint: skip-file


def xml_get_mark_as_junk(input_item_ids, is_junk=None, move_item=None):

    is_junk = True if is_junk is None else is_junk
    move_item = True if move_item is None else move_item

    input_item_ids = [x.strip() for x in input_item_ids.split(",")]

    item_ids = M.ItemIds()
    [item_ids.append(T.ItemId({"Id": x})) for x in input_item_ids]

    mark_as_junk = M.MarkAsJunk({"IsJunk": (str(is_junk)).lower()}, {"MoveItem": (str(move_item)).lower()}, item_ids)

    return mark_as_junk


def xml_get_restriction(greater_than_time=None, message_id=None):

    filters = []

    if greater_than_time:
        greater_than_time = T.IsGreaterThan(
            T.FieldURI({"FieldURI": "item:LastModifiedTime"}), T.FieldURIOrConstant(T.Constant({"Value": greater_than_time}))
        )
        filters.append(greater_than_time)

    if message_id:
        message_id = T.IsNotEqualTo(T.FieldURI({"FieldURI": "item:ItemId"}), T.FieldURIOrConstant(T.Constant({"Value": message_id})))
        filters.append(message_id)

    if not filters:
        return None

    if len(filters) > 1:
        restriction = M.Restriction(T.And(*filters))
    else:
        restriction = M.Restriction(*filters)

    return restriction


def xml_get_email_ids(user, folder_id, order, offset, max_emails, restriction):

    elements = []

    additional_properties = T.AdditionalProperties(T.FieldURI({"FieldURI": "item:LastModifiedTime"}))

    item_shape = M.ItemShape(T.BaseShape("IdOnly"), additional_properties)

    elements.append(item_shape)

    page = M.IndexedPageItemView({"MaxEntriesReturned": str(max_emails)}, {"Offset": str(offset)}, {"BasePoint": "Beginning"})

    elements.append(page)

    if restriction:
        elements.append(restriction)

    sort_order = M.SortOrder(T.FieldOrder({"Order": order}, T.FieldURI({"FieldURI": "item:LastModifiedTime"})))

    elements.append(sort_order)

    # Treat it as a "inbox"
    parent_folder_ids = M.ParentFolderIds(
        T.DistinguishedFolderId({"Id": folder_id}, T.Mailbox(T.EmailAddress(UnicodeDammit(user).unicode_markup.encode("utf-8").decode("utf-8"))))
    )

    if folder_id != "inbox":
        parent_folder_ids = M.ParentFolderIds(T.FolderId({"Id": folder_id}))

    elements.append(parent_folder_ids)

    find_item = M.FindItem({"Traversal": "Shallow"}, *elements)

    return find_item


def xml_get_resolve_names(email):
    """
    https://msdn.microsoft.com/en-us/library/office/aa563518(v=exchg.150).aspx
    """

    return M.ResolveNames(
        {"ReturnFullContactData": "true"}, M.UnresolvedEntry(UnicodeDammit(email).unicode_markup.encode("utf-8").decode("utf-8"))
    )


def get_expand_dl(email):
    """
    https://msdn.microsoft.com/en-us/library/office/aa494152(v=exchg.150).aspx
    """

    # All documentation says that Mailbox should be a "T", but that just throws an error
    # it has to be an "M" for things to work
    return M.ExpandDL(M.Mailbox(T.EmailAddress(UnicodeDammit(email).unicode_markup.encode("utf-8").decode("utf-8"))))


def xml_get_attachments_data(attachment_ids_to_query):
    """
    https://msdn.microsoft.com/en-us/library/office/aa494316(v=exchg.150).aspx
    FieldURI: InternetMessageHeaders does _not_ return all the headers
    PropertyTag 0x007D is required, which points to PR_TRANSPORT_MESSAGE_HEADERS
    """

    additional_properties = T.AdditionalProperties(
        T.FieldURI({"FieldURI": "message:Sender"}),
        T.FieldURI({"FieldURI": "message:InternetMessageId"}),
        T.FieldURI({"FieldURI": "item:DateTimeReceived"}),
        T.FieldURI({"FieldURI": "item:Attachments"}),
        T.ExtendedFieldURI({"PropertyTag": EXTENDED_PROPERTY_HEADERS, "PropertyType": "String"}),
        T.ExtendedFieldURI({"PropertyTag": EXTENDED_PROPERTY_BODY_TEXT, "PropertyType": "String"}),
        T.FieldURI({"FieldURI": "item:LastModifiedTime"}),
    )

    attachment_shape = M.AttachmentShape(T.IncludeMimeContent("true"), T.BodyType("Best"), T.FilterHtmlContent("true"), additional_properties)

    attachment_ids = M.AttachmentIds()
    [attachment_ids.append(T.AttachmentId({"Id": x})) for x in attachment_ids_to_query]

    get_attachments = M.GetAttachment(attachment_shape, attachment_ids)

    return get_attachments


def xml_get_emails_data(email_ids):
    """
    https://msdn.microsoft.com/en-us/library/office/aa566013(v=exchg.150).aspx
    FieldURI: InternetMessageHeaders does _not_ return all the headers
    PropertyTag 0x007D is required, which points to PR_TRANSPORT_MESSAGE_HEADERS
    """

    additional_properties = T.AdditionalProperties(
        T.FieldURI({"FieldURI": "item:Subject"}),
        T.FieldURI({"FieldURI": "message:From"}),
        T.FieldURI({"FieldURI": "message:Sender"}),
        T.FieldURI({"FieldURI": "message:InternetMessageId"}),
        T.FieldURI({"FieldURI": "item:Categories"}),
        T.ExtendedFieldURI({"PropertyTag": EXTENDED_PROPERTY_HEADERS, "PropertyType": "String"}),
        T.ExtendedFieldURI({"PropertyTag": EXTENDED_PROPERTY_BODY_TEXT, "PropertyType": "String"}),
        T.FieldURI({"FieldURI": "item:DateTimeReceived"}),
        T.FieldURI({"FieldURI": "item:LastModifiedTime"}),
        T.FieldURI({"FieldURI": "item:Body"})
    )

    item_shape = M.ItemShape(T.BaseShape("Default"), T.IncludeMimeContent("true"), additional_properties)

    item_ids = M.ItemIds()
    [item_ids.append(T.ItemId({"Id": x})) for x in email_ids]

    get_item = M.GetItem(item_shape, item_ids)

    return get_item


def get_search_request_aqs(folder_ids, aqs, email_range="0-10"):

    elements = []

    # Item Shape
    additional_properties = T.AdditionalProperties(
        T.FieldURI({"FieldURI": "item:Subject"}),
        T.FieldURI({"FieldURI": "message:From"}),
        T.FieldURI({"FieldURI": "message:Sender"}),
        T.FieldURI({"FieldURI": "message:InternetMessageId"}),
        T.FieldURI({"FieldURI": "item:DateTimeReceived"}),
        T.ExtendedFieldURI({"PropertySetId": "aa3df801-4fc7-401f-bbc1-7c93d6498c2e", "PropertyName": "ItemIndex", "PropertyType": "Integer"}),
    )

    item_shape = M.ItemShape(T.BaseShape("IdOnly"), additional_properties)
    elements.append(item_shape)

    # IndexedPageItemView
    mini, maxi = (int(x) for x in email_range.split("-"))

    page = M.IndexedPageItemView({"MaxEntriesReturned": str(maxi - mini + 1)}, {"Offset": str(mini)}, {"BasePoint": "Beginning"})
    elements.append(page)

    # sort order
    sort_order = M.SortOrder(T.FieldOrder({"Order": "Descending"}, T.FieldURI({"FieldURI": "item:DateTimeReceived"})))
    elements.append(sort_order)

    # parent folder ids
    t_folder_ids = [T.FolderId({"Id": x}) for x in folder_ids]

    parent_folder_ids = M.ParentFolderIds(*t_folder_ids)

    elements.append(parent_folder_ids)

    # query string
    query_string = M.QueryString(UnicodeDammit(aqs).unicode_markup.encode("utf-8").decode("utf-8"))
    elements.append(query_string)

    find_item = M.FindItem({"Traversal": "Shallow"}, *elements)

    return find_item


def get_search_request_filter(folder_ids, subject=None, sender=None, body=None, int_msg_id=None, restriction=None, email_range="0-10"):
    """
    Link for Restriction node
    https://msdn.microsoft.com/en-us/library/office/aa563791(v=exchg.150).aspx

    Link for the FieldURI"s
    https://msdn.microsoft.com/en-us/library/office/aa494315(v=exchg.150).aspx

    Link to article that explains how all this fits in
    https://msdn.microsoft.com/en-us/library/office/dn579422(v=exchg.150).aspx
    """

    elements = []

    # Item Shape
    additional_properties = T.AdditionalProperties(
        T.FieldURI({"FieldURI": "item:Subject"}),
        T.FieldURI({"FieldURI": "message:From"}),
        T.FieldURI({"FieldURI": "message:Sender"}),
        T.FieldURI({"FieldURI": "message:InternetMessageId"}),
        T.FieldURI({"FieldURI": "item:DateTimeReceived"}),
        T.ExtendedFieldURI({"PropertySetId": "aa3df801-4fc7-401f-bbc1-7c93d6498c2e", "PropertyName": "ItemIndex", "PropertyType": "Integer"}),
    )

    item_shape = M.ItemShape(T.BaseShape("IdOnly"), additional_properties)
    elements.append(item_shape)

    # IndexedPageItemView
    mini, maxi = (int(x) for x in email_range.split("-"))

    page = M.IndexedPageItemView({"MaxEntriesReturned": str(maxi - mini + 1)}, {"Offset": str(mini)}, {"BasePoint": "Beginning"})
    elements.append(page)

    # Restriction
    if restriction is None:
        filters = []

        if subject:
            sub_filt = T.Contains(
                {"ContainmentMode": "Substring", "ContainmentComparison": "IgnoreCase"},
                T.FieldURI({"FieldURI": "item:Subject"}),
                T.Constant({"Value": UnicodeDammit(subject).unicode_markup.encode("utf-8").decode("utf-8")}),
            )
            filters.append(sub_filt)

        if sender:
            sender_filter = T.IsEqualTo(
                T.FieldURI({"FieldURI": "message:Sender"}),
                T.FieldURIOrConstant(T.Constant({"Value": UnicodeDammit(sender).unicode_markup.encode("utf-8").decode("utf-8")})),
            )
            filters.append(sender_filter)

        if int_msg_id:
            sender_filter = T.IsEqualTo(
                T.FieldURI({"FieldURI": "message:InternetMessageId"}),
                T.FieldURIOrConstant(T.Constant({"Value": UnicodeDammit(int_msg_id).unicode_markup.encode("utf-8").decode("utf-8")})),
            )
            filters.append(sender_filter)

        if body:
            body_filter = T.Contains(
                {"ContainmentMode": "Substring", "ContainmentComparison": "IgnoreCase"},
                T.FieldURI({"FieldURI": "item:Body"}),
                T.Constant({"Value": UnicodeDammit(body).unicode_markup.encode("utf-8").decode("utf-8")}),
            )
            filters.append(body_filter)

        if filters:
            if len(filters) > 1:
                restriction = M.Restriction(T.And(*filters))
            else:
                restriction = M.Restriction(*filters)

    if restriction is not None:
        elements.append(restriction)

    # sort order
    sort_order = M.SortOrder(T.FieldOrder({"Order": "Descending"}, T.FieldURI({"FieldURI": "item:DateTimeReceived"})))
    elements.append(sort_order)

    # parent folder ids
    t_folder_ids = [T.FolderId({"Id": x}) for x in folder_ids]

    parent_folder_ids = M.ParentFolderIds(*t_folder_ids)

    elements.append(parent_folder_ids)

    find_item = M.FindItem({"Traversal": "Shallow"}, *elements)

    return find_item


def get_update_email(email_id, change_key, categories=None, subject=None):

    item_id = T.ItemId({"Id": email_id, "ChangeKey": change_key})

    update_node = []

    if categories is not None:
        category_string_list = []

        for curr_category in categories:
            category_string_list.append(T.String(curr_category))

        cat_node = T.SetItemField(T.FieldURI({"FieldURI": "item:Categories"}), T.Message(T.Categories(*category_string_list)))
        update_node.append(cat_node)

    if subject is not None:
        sub_node = T.SetItemField(T.FieldURI({"FieldURI": "item:Subject"}), T.Message(T.Subject(subject)))
        update_node.append(sub_node)

    update_item = M.UpdateItem(
        {"MessageDisposition": "SaveOnly", "ConflictResolution": "AlwaysOverwrite"},
        M.ItemChanges(T.ItemChange(item_id, T.Updates(*update_node))),
    )

    return update_item


def get_delete_email(message_ids):

    if not isinstance(message_ids, list):
        message_ids = [message_ids]

    item_ids = [T.ItemId({"Id": x}) for x in message_ids]
    item_ids_m = M.ItemIds(*item_ids)

    del_item = M.DeleteItem({"DeleteType": "HardDelete"}, item_ids_m)

    return del_item


def get_move_email(message_id, folder_id):

    return M.MoveItem(M.ToFolderId(T.FolderId({"Id": folder_id})), M.ItemIds(T.ItemId({"Id": message_id})))


def get_copy_email(message_id, folder_id):

    return M.CopyItem(M.ToFolderId(T.FolderId({"Id": folder_id})), M.ItemIds(T.ItemId({"Id": message_id})))


def xml_get_root_folder_id(user, root_folder_id="root"):
    folder_shape = M.FolderShape(T.BaseShape("IdOnly"))
    if root_folder_id == "publicfoldersroot":
        par_folder_id = M.ParentFolderIds(T.DistinguishedFolderId({"Id": root_folder_id}))
        traversal = {"Traversal": "Shallow"}
    else:
        par_folder_id = M.ParentFolderIds(
            T.DistinguishedFolderId(
                {"Id": root_folder_id}, T.Mailbox(T.EmailAddress(UnicodeDammit(user).unicode_markup.encode("utf-8").decode("utf-8")))
            )
        )

        traversal = {"Traversal": "Deep"}

    return M.FindFolder(traversal, folder_shape, par_folder_id)


def xml_get_children_info(user, child_folder_name=None, parent_folder_id="root", query_range=None):

    elements = []

    folder_shape = M.FolderShape(
        T.BaseShape("IdOnly"),
        T.AdditionalProperties(
            T.FieldURI({"FieldURI": "folder:FolderId"}),
            T.FieldURI({"FieldURI": "folder:FolderClass"}),
            T.FieldURI({"FieldURI": "folder:ChildFolderCount"}),
            T.FieldURI({"FieldURI": "folder:ParentFolderId"}),
            T.ExtendedFieldURI({"PropertyTag": "26293", "PropertyType": "String"}),
            T.FieldURI({"FieldURI": "folder:DisplayName"}),
        ),
    )

    elements.append(folder_shape)

    if query_range:
        mini, maxi = (int(x) for x in query_range.split("-"))
        page = M.IndexedPageFolderView({"MaxEntriesReturned": str(maxi - mini + 1)}, {"Offset": str(mini)}, {"BasePoint": "Beginning"})

        elements.append(page)

    filters = []
    restriction = None

    note_equal_to = T.IsEqualTo(T.FieldURI({"FieldURI": "folder:FolderClass"}), T.FieldURIOrConstant(T.Constant({"Value": "IPF.Note"})))
    filters.append(note_equal_to)

    traversal = {"Traversal": "Deep"}

    if child_folder_name:
        display_name_equal_to = T.IsEqualTo(
            T.FieldURI({"FieldURI": "folder:DisplayName"}),
            T.FieldURIOrConstant(T.Constant({"Value": UnicodeDammit(child_folder_name).unicode_markup.encode("utf-8").decode("utf-8")})),
        )
        filters.append(display_name_equal_to)

    if filters:
        if len(filters) > 1:
            restriction = M.Restriction(T.And(*filters))
        else:
            restriction = M.Restriction(*filters)

    if user:
        if parent_folder_id == "root":
            par_folder_id = M.ParentFolderIds(
                T.DistinguishedFolderId(
                    {"Id": parent_folder_id}, T.Mailbox(T.EmailAddress(UnicodeDammit(user).unicode_markup.encode("utf-8").decode("utf-8")))
                )
            )
        elif parent_folder_id == "publicfoldersroot":
            par_folder_id = M.ParentFolderIds(T.DistinguishedFolderId({"Id": parent_folder_id}))
            traversal["Traversal"] = "Shallow"
        else:
            par_folder_id = M.ParentFolderIds(T.FolderId({"Id": parent_folder_id}))
    else:
        par_folder_id = M.ParentFolderIds(T.DistinguishedFolderId({"Id": parent_folder_id}))

    if restriction is not None:
        elements.append(restriction)

    elements.append(par_folder_id)

    """
    if (restriction is not None):
        return M.FindFolder(
                {"Traversal": "Deep"},
                folder_shape,
                restriction,
                par_folder_id)
                """

    return M.FindFolder(traversal, *elements)


def add_to_envelope(lxml_obj, target_user=None):

    header = S.Header(T.RequestServerVersion({"Version": "Exchange2013"}))

    if target_user:
        impersonation = T.ExchangeImpersonation(
            T.ConnectingSID(T.SmtpAddress(UnicodeDammit(target_user).unicode_markup.encode("utf-8").decode("utf-8")))
        )
        header.append(impersonation)

    return S.Envelope(header, S.Body(lxml_obj))


def get_string(lxml_obj):
    return etree.tostring(lxml_obj, encoding="utf-8")
