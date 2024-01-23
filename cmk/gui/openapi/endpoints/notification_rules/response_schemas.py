#!/usr/bin/env python3
# Copyright (C) 2022 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.


from collections.abc import Mapping
from typing import Any, get_args

from marshmallow.decorators import pre_dump

from cmk.utils.notify_types import BuiltInPluginNames, PluginOptions

from cmk.gui.fields import AuxTagIDField, TagGroupIDField
from cmk.gui.fields.utils import BaseSchema
from cmk.gui.openapi.endpoints.notification_rules.common_schemas import (
    AsciiEmailParamsResponse,
    Checkbox,
    CheckboxHostEventType,
    CheckboxRestrictNotificationNumbers,
    CheckboxServiceEventType,
    CheckboxThrottlePeriodicNotifcations,
    CheckboxWithFolderStr,
    CheckboxWithFromToServiceLevels,
    CheckboxWithListOfLabels,
    CheckboxWithListOfServiceGroupsRegex,
    CheckboxWithListOfStr,
    CheckboxWithStrValue,
    CiscoWebexPluginResponse,
    HTMLEmailParamsResponse,
    IlertPluginResponse,
    JiraPluginResponse,
    MatchCustomMacros,
    MatchEventConsoleAlertsResponse,
    MAX_BULK_SIZE,
    MkEventParamsResponse,
    MSTeamsPluginResponse,
    NOTIFICATION_BULKS_BASED_ON,
    NOTIFICATION_BULKS_BASED_ON_CUSTOM_MACROS,
    OpenGeniePluginResponse,
    PagerDutyPluginResponse,
    PushOverPluginResponse,
    RulePropertiesAllowDeactivate,
    RulePropertiesComment,
    RulePropertiesDescription,
    RulePropertiesDocURL,
    RulePropertiesDoNotApplyRule,
    ServiceNowPluginResponse,
    Signl4PluginResponse,
    SlackPluginResponse,
    SMSAPIPluginResponse,
    SMSPluginBase,
    SpectrumPluginBase,
    TIME_HORIZON,
    TIME_PERIOD,
    VictoropsPluginResponse,
    WHEN_TO_BULK,
)
from cmk.gui.openapi.endpoints.notification_rules.request_example import (
    notification_rule_request_example,
)
from cmk.gui.openapi.restful_objects.response_schemas import DomainObject, DomainObjectCollection
from cmk.gui.rest_api_types.notifications_rule_types import PluginType
from cmk.gui.watolib.tags import load_all_tag_config_read_only

from cmk import fields


class MatchHostTags(BaseSchema):
    tag_type = fields.String(
        example="aux_tag", description="If it's an aux tag id or a group tag tag id."
    )
    tag_group_id = TagGroupIDField(
        example="agent",
        required=False,
        description="If the tag_type is 'tag_group', the id of that group is shown here.",
    )
    operator = fields.String(
        description="This describes the matching action",
    )
    tag_id = AuxTagIDField(
        example="checkmk-agent",
        description="Tag groups tag ids are available via the host tag group endpoint.",
    )


class CheckboxMatchHostTags(Checkbox):
    value = fields.List(fields.Nested(MatchHostTags))

    @pre_dump(pass_many=True)
    def pre_dump(self, data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        tag_config = load_all_tag_config_read_only()
        aux_tags = [tag.id for tag in tag_config.aux_tag_list]
        tag_groups_n_tags = [
            (group.id, [tag.id for tag in group.tags]) for group in tag_config.tag_groups
        ]

        if (raw_value := data.get("value")) is not None:
            data["value"] = []

            for tag_id in raw_value:
                raw_id = tag_id.replace("!", "")
                if raw_id in aux_tags:
                    auxtag = {
                        "tag_type": "aux_tag",
                        "tag_id": raw_id,
                        "operator": "is_not_set" if tag_id[0] == "!" else "is_set",
                    }
                    data["value"].append(auxtag)

                for tag_group_id, tag_ids in tag_groups_n_tags:
                    if raw_id in tag_ids:
                        grouptag = {
                            "tag_type": "tag_group",
                            "tag_group_id": tag_group_id,
                            "operator": "is_not" if tag_id[0] == "!" else "is",
                            "tag_id": raw_id,
                        }
                        data["value"].append(grouptag)

        return data


# -----------------------------------------------------------------------------------------


class RulePropertiesAttributes(BaseSchema):
    description = RulePropertiesDescription(required=True)
    comment = RulePropertiesComment(required=True)
    documentation_url = RulePropertiesDocURL(required=True)
    do_not_apply_this_rule = RulePropertiesDoNotApplyRule(required=True)
    allow_users_to_deactivate = RulePropertiesAllowDeactivate(required=True)


class PluginBase(BaseSchema):
    option = fields.String(
        enum=[
            PluginOptions.CANCEL.value,
            PluginOptions.WITH_PARAMS.value,
            PluginOptions.WITH_CUSTOM_PARAMS.value,
        ],
        required=True,
        example=PluginOptions.CANCEL.value,
    )

    def dump(self, obj: dict[str, Any], *args: Any, **kwargs: Any) -> Mapping:
        if obj["plugin_params"]["plugin_name"] not in list(get_args(BuiltInPluginNames)):
            return obj

        schema_mapper: Mapping[BuiltInPluginNames, type[BaseSchema]] = {
            "mail": HTMLEmailParamsResponse,
            "cisco_webex_teams": CiscoWebexPluginResponse,
            "mkeventd": MkEventParamsResponse,
            "asciimail": AsciiEmailParamsResponse,
            "ilert": IlertPluginResponse,
            "jira_issues": JiraPluginResponse,
            "opsgenie_issues": OpenGeniePluginResponse,
            "pagerduty": PagerDutyPluginResponse,
            "pushover": PushOverPluginResponse,
            "servicenow": ServiceNowPluginResponse,
            "signl4": Signl4PluginResponse,
            "slack": SlackPluginResponse,
            "sms_api": SMSAPIPluginResponse,
            "sms": SMSPluginBase,
            "spectrum": SpectrumPluginBase,
            "victorops": VictoropsPluginResponse,
            "msteams": MSTeamsPluginResponse,
        }

        plugin_params: PluginType = obj["plugin_params"]
        plugin_name: BuiltInPluginNames = plugin_params["plugin_name"]
        schema_to_use = schema_mapper[plugin_name]
        obj.update({"plugin_params": schema_to_use().dump(plugin_params)})
        return obj


class NotificationBulkingCommonAttributes(Checkbox):
    time_horizon = TIME_HORIZON
    max_bulk_size = MAX_BULK_SIZE
    notification_bulks_based_on = NOTIFICATION_BULKS_BASED_ON
    notification_bulks_based_on_custom_macros = NOTIFICATION_BULKS_BASED_ON_CUSTOM_MACROS
    subject_for_bulk_notifications = fields.Nested(
        CheckboxWithStrValue,
    )


class BulkOutsideTimePeriodValue(Checkbox):
    value = fields.Nested(NotificationBulkingCommonAttributes)


class NotificationBulking(NotificationBulkingCommonAttributes):
    time_period = TIME_PERIOD
    bulk_outside_timeperiod = fields.Nested(
        BulkOutsideTimePeriodValue,
        required=True,
    )


class WhenToBulk(BaseSchema):
    when_to_bulk = WHEN_TO_BULK
    params = fields.Nested(
        NotificationBulking,
        required=True,
    )


class NotificationBulkingCheckbox(Checkbox):
    value = fields.Nested(
        WhenToBulk,
        required=True,
    )


class NotificationPlugin(BaseSchema):
    notify_plugin = fields.Nested(PluginBase)
    notification_bulking = fields.Nested(NotificationBulkingCheckbox)


class ContactSelectionAttributes(BaseSchema):
    all_contacts_of_the_notified_object = fields.Nested(Checkbox)
    all_users = fields.Nested(Checkbox)
    all_users_with_an_email_address = fields.Nested(Checkbox)
    the_following_users = fields.Nested(CheckboxWithListOfStr)
    members_of_contact_groups = fields.Nested(CheckboxWithListOfStr)
    explicit_email_addresses = fields.Nested(CheckboxWithListOfStr)
    restrict_by_custom_macros = fields.Nested(MatchCustomMacros)
    restrict_by_contact_groups = fields.Nested(CheckboxWithListOfStr)


class ConditionsAttributes(BaseSchema):
    match_sites = fields.Nested(CheckboxWithListOfStr)
    match_folder = fields.Nested(CheckboxWithFolderStr)
    match_host_tags = fields.Nested(CheckboxMatchHostTags)
    match_host_labels = fields.Nested(CheckboxWithListOfLabels)
    match_host_groups = fields.Nested(CheckboxWithListOfStr)
    match_hosts = fields.Nested(CheckboxWithListOfStr)
    match_exclude_hosts = fields.Nested(CheckboxWithListOfStr)
    match_service_labels = fields.Nested(CheckboxWithListOfLabels)
    match_service_groups = fields.Nested(CheckboxWithListOfStr)
    match_exclude_service_groups = fields.Nested(CheckboxWithListOfStr)
    match_service_groups_regex = fields.Nested(CheckboxWithListOfServiceGroupsRegex)
    match_exclude_service_groups_regex = fields.Nested(CheckboxWithListOfServiceGroupsRegex)
    match_services = fields.Nested(CheckboxWithListOfStr)
    match_exclude_services = fields.Nested(CheckboxWithListOfStr)
    match_check_types = fields.Nested(CheckboxWithListOfStr)
    match_plugin_output = fields.Nested(CheckboxWithStrValue)
    match_contact_groups = fields.Nested(CheckboxWithListOfStr)
    match_service_levels = fields.Nested(CheckboxWithFromToServiceLevels)
    match_only_during_time_period = fields.Nested(CheckboxWithStrValue)
    match_host_event_type = fields.Nested(CheckboxHostEventType)
    match_service_event_type = fields.Nested(CheckboxServiceEventType)
    restrict_to_notification_numbers = fields.Nested(CheckboxRestrictNotificationNumbers)
    throttle_periodic_notifications = fields.Nested(CheckboxThrottlePeriodicNotifcations)
    match_notification_comment = fields.Nested(CheckboxWithStrValue)
    event_console_alerts = fields.Nested(MatchEventConsoleAlertsResponse)


class NotificationRuleAttributes(BaseSchema):
    rule_properties = fields.Nested(RulePropertiesAttributes)
    notification_method = fields.Nested(NotificationPlugin)
    contact_selection = fields.Nested(ContactSelectionAttributes)
    conditions = fields.Nested(ConditionsAttributes)


class NotificationRuleConfig(BaseSchema):
    rule_config = fields.Nested(
        NotificationRuleAttributes,
    )


class NotificationRuleResponse(DomainObject):
    domainType = fields.Constant(
        "rule_notifications",
        description="The domain type of the object.",
    )
    extensions = fields.Nested(
        NotificationRuleConfig,
        description="The configuration attributes of a notification rule.",
        example={"rule_config": notification_rule_request_example()},
    )


class NotificationRuleResponseCollection(DomainObjectCollection):
    domainType = fields.Constant(
        "rule_notifications",
        description="The domain type of the objects in the collection.",
    )
    value = fields.List(
        fields.Nested(NotificationRuleResponse),
        description="A list of notification rule objects.",
        example=[
            {
                "links": [],
                "domainType": "rule_notifications",
                "id": "1",
                "title": "Rule Description",
                "members": {},
                "extensions": {"rule_config": notification_rule_request_example()},
            }
        ],
    )
