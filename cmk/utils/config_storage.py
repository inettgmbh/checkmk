#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.
import abc
import io
import pickle
import pprint
from typing import Any, Dict, List, Optional, Set, Tuple
from cmk.utils import store
from cmk.utils.rulesets.tuple_rulesets import (ALL_HOSTS, ALL_SERVICES)

AttributeType = Tuple[str, str, Dict[str, Any], str]  # host attr, cmk.base var name, value, title
GroupRuleType = Dict[str, Dict[str, List[str]]]
WATO_FILE_HEADER = "# Created by WATO\n# encoding: utf-8\n\n"


class ABCHostsStorage(abc.ABC):
    __slots__ = ['_out', '_use_pprint']

    def __init__(self, use_pprint: bool) -> None:
        super(ABCHostsStorage, self).__init__()
        self._out = io.StringIO()
        self._use_pprint = use_pprint

    def getvalue(self) -> str:
        return self._out.getvalue()

    def save(self, s: str) -> None:
        self._out.write(s)

    def format_config_value(self, value: Any) -> str:
        return pprint.pformat(value) if self._use_pprint else repr(value)

    def save_group_rules_list(self, group_rules_list: List[Tuple[List[GroupRuleType],
                                                                 Optional[bool]]]):
        for group_rules, use_for_service in group_rules_list:
            self._save_group_rules(group_rules, use_for_service)

    @abc.abstractmethod
    def _save_group_rules(self, group_rules: List[GroupRuleType],
                          use_for_services: Optional[bool]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def save_all_hosts(self, all_hosts: List[str]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def save_clusters(self, clusters: Dict[str, List[str]]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def save_host_tags(self, host_tags: Dict[str, Any]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def save_host_labels(self, host_labels: Dict[str, Any]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def save_extra_host_conf(self, custom_macros: Dict[str, Dict[str, str]]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def save_explicit_host_settings(self, explicit_host_settings: Dict[str, Dict[str, str]]):
        raise NotImplementedError()

    @abc.abstractmethod
    def save_attributes(self, attribute_mappings: List[AttributeType]):
        raise NotImplementedError()

    @abc.abstractmethod
    def save_contact_groups(self, groups: Tuple[Set[bool], Set[bool], bool]):
        raise NotImplementedError()

    @abc.abstractmethod
    def save_cleaned_hosts(self, cleaned_hosts: Dict[str, Dict[str, Any]]) -> None:
        """Write information about all host attributes into special variable - even
        values stored for check_mk as well."""
        raise NotImplementedError()

    def write(self, filename: str) -> None:
        store.save_file(filename, self.getvalue())


class StandardHostsStorage(ABCHostsStorage):
    """Saves config in old good mk format: arbitrary python code"""
    def __init__(self, use_pprint: bool = False) -> None:
        super(StandardHostsStorage, self).__init__(use_pprint)
        self.save(WATO_FILE_HEADER)

    def _save_group_rules(self, group_rules: List[GroupRuleType],
                          use_for_services: Optional[bool]) -> None:
        self.save("\nhost_contactgroups += %s\n\n" % self.format_config_value(group_rules))

        if use_for_services:
            self.save("\nservice_contactgroups += %s\n\n" % self.format_config_value(group_rules))

    def save_all_hosts(self, all_hosts: List[str]) -> None:
        if all_hosts:
            self.save("all_hosts += %s\n" % self.format_config_value(all_hosts))

    def save_clusters(self, clusters: Dict[str, List[str]]) -> None:
        if clusters:
            self.save("\nclusters.update(%s)\n" % self.format_config_value(clusters))

    def save_host_tags(self, host_tags: Dict[str, Any]) -> None:
        self.save("\nhost_tags.update(%s)\n" % self.format_config_value(host_tags))

    def save_host_labels(self, host_labels: Dict[str, Any]) -> None:
        self.save("\nhost_labels.update(%s)\n" % self.format_config_value(host_labels))

    def save_extra_host_conf(self, custom_macros: Dict[str, Dict[str, str]]) -> None:
        for custom_varname, entries in custom_macros.items():
            macrolist = []
            for hostname, nagstring in entries.items():
                macrolist.append((nagstring, [hostname]))
            if len(macrolist) > 0:
                self.save("\n# Settings for %s\n" % custom_varname)
                self.save("extra_host_conf.setdefault(%r, []).extend(\n" % custom_varname)
                self.save("  %s)\n" % self.format_config_value(macrolist))

    def save_explicit_host_settings(self, explicit_host_settings: Dict[str, Dict[str, str]]):
        for varname, entries in explicit_host_settings.items():
            if len(entries) > 0:
                self.save("\n# Explicit settings for %s\n" % varname)
                self.save("explicit_host_conf.setdefault(%r, {})\n" % varname)
                self.save("explicit_host_conf['%s'].update(%r)\n" % (varname, entries))

    def save_attributes(self, attribute_mappings: List[AttributeType]):
        for _, cmk_base_varname, dictionary, title in attribute_mappings:
            if dictionary:
                self.save("\n# %s\n" % title)
                self.save("%s.update(" % cmk_base_varname)
                self.save(self.format_config_value(dictionary))
                self.save(")\n")

    def save_contact_groups(self, groups: Tuple[Set[bool], Set[bool], bool]):
        # If the contact groups of the folder are set to be used for the monitoring,
        # we create an according rule for the folder here and an according rule for
        # each host that has an explicit setting for that attribute (see above).
        _permitted_groups, contact_groups, use_for_services = groups
        if contact_groups:
            self.save("\nhost_contactgroups.insert(0, \n"
                      "  {'value': %r, 'condition': {'host_folder': '/%%s/' %% FOLDER_PATH}})\n" %
                      list(contact_groups))
            if use_for_services:
                # Currently service_contactgroups requires single values. Lists are not supported
                for cg in contact_groups:
                    self.save(
                        "\nservice_contactgroups.insert(0, \n"
                        "  {'value': %r, 'condition': {'host_folder': '/%%s/' %% FOLDER_PATH}})\n" %
                        cg)

    def save_cleaned_hosts(self, cleaned_hosts: Dict[str, Dict[str, Any]]) -> None:
        """Write information about all host attributes into special variable - even
        values stored for check_mk as well."""
        self.save("\n# Host attributes (needed for WATO)\n")
        self.save("host_attributes.update(\n%s)\n" % self.format_config_value(cleaned_hosts))


# TODO(sk): deprecated and will be removed, in code base as areference
class RawHostsStorage(ABCHostsStorage):
    """Saves config in raw format: as text with python dicts and lists with predefined names"""
    def __init__(self, use_pprint: bool = False) -> None:
        super(RawHostsStorage, self).__init__(use_pprint)
        self.save("{\n")

    def write(self, filename: str) -> None:
        self.save("}\n")
        store.save_file(filename + ".cfg", self.getvalue())

    def _save_group_rules(self, group_rules: List[GroupRuleType],
                          use_for_services: Optional[bool]) -> None:
        self.save("    'host_contactgroups': %s,\n" % self.format_config_value(group_rules))

        if use_for_services:
            self.save("   'service_contactgroups': %s,\n" % self.format_config_value(group_rules))

    def save_all_hosts(self, all_hosts: List[str]) -> None:
        if all_hosts:
            self.save("    'all_hosts': %s,\n" % self.format_config_value(all_hosts))

    def save_clusters(self, clusters: Dict[str, List[str]]) -> None:
        if clusters:
            self.save("    'clusters': %s,\n" % self.format_config_value(clusters))

    def save_host_tags(self, host_tags: Dict[str, Any]) -> None:
        self.save("    'host_tags': %s,\n" % self.format_config_value(host_tags))

    def save_host_labels(self, host_labels: Dict[str, Any]) -> None:
        self.save("    'host_labels': %s,\n" % self.format_config_value(host_labels))

    def save_extra_host_conf(self, custom_macros: Dict[str, Dict[str, str]]) -> None:
        self.save("    'custom_macros': {\n")
        for custom_varname, entries in custom_macros.items():
            macrolist = []
            for hostname, nagstring in entries.items():
                macrolist.append((nagstring, [hostname]))
            if len(macrolist) > 0:
                self.save("        '%r': %s, \n" % (
                    custom_varname,
                    self.format_config_value(macrolist),
                ))
        self.save("    },\n")

    def save_explicit_host_settings(self, explicit_host_settings: Dict[str, Dict[str, str]]):
        self.save("    'explicit_host_conf': {\n")
        for varname, entries in explicit_host_settings.items():
            if len(entries) > 0:
                self.save("        '%s': %r,\n" % (varname, entries))
        self.save("    },\n")

    def save_attributes(self, attribute_mappings: List[AttributeType]):
        self.save("    'attributes': {\n")
        for _, cmk_base_varname, dictionary, _ in attribute_mappings:
            if dictionary:
                self.save("        '%s': %s,\n" % (
                    cmk_base_varname,
                    self.format_config_value(dictionary),
                ))
        self.save("    },\n")

    def save_contact_groups(self, groups: Tuple[Set[bool], Set[bool], bool]):
        # If the contact groups of the folder are set to be used for the monitoring,
        # we create an according rule for the folder here and an according rule for
        # each host that has an explicit setting for that attribute (see above).
        _permitted_groups, contact_groups, use_for_services = groups
        self.save("    'contact_groups': {\n")
        if contact_groups:
            self.save("        'host_contactgroups':"
                      "  {'value': %r, 'condition': {'host_folder': '/%%s/' %% FOLDER_PATH}}\n" %
                      list(contact_groups))
            if use_for_services:
                # Currently service_contactgroups requires single values. Lists are not supported
                for cg in contact_groups:
                    self.save(
                        "\nservice_contactgroups.insert(0, \n"
                        "  {'value': %r, 'condition': {'host_folder': '/%%s/' %% FOLDER_PATH}})\n" %
                        cg)
        self.save("    },\n")

    def save_cleaned_hosts(self, cleaned_hosts: Dict[str, Dict[str, Any]]) -> None:
        """Write information about all host attributes into special variable - even
        values stored for check_mk as well."""
        self.save("    'host_attributes': %s,\n" % self.format_config_value(cleaned_hosts))


class PickleHostStorage(ABCHostsStorage):
    """Saves config in pkl format: as pickle of dicts and lists with predefined names"""
    __slots__ = ['_data']

    def __init__(self, use_pprint: bool = False) -> None:
        super(PickleHostStorage, self).__init__(use_pprint)
        self._data: Dict[str, Any] = {}

    def write(self, filename: str) -> None:
        store.save_file(filename + ".pkl", pickle.dumps(self._data))

    def save_all_hosts(self, all_hosts: List[str]) -> None:
        self._data["all_hosts"] = all_hosts

    def save_clusters(self, clusters: Dict[str, List[str]]) -> None:
        self._data["clusters"] = clusters

    def _save_group_rules(self, group_rules: List[GroupRuleType],
                          use_for_services: Optional[bool]) -> None:
        self._data["host_contactgroups"] = group_rules
        if use_for_services:
            self._data["service_contactgroups"] = group_rules

    def save_host_tags(self, host_tags: Dict[str, Any]) -> None:
        self._data["host_tags"] = host_tags

    def save_host_labels(self, host_labels: Dict[str, Any]) -> None:
        self._data["host_labels"] = host_labels

    def save_extra_host_conf(self, custom_macros: Dict[str, Dict[str, str]]) -> None:
        for custom_varname, entries in custom_macros.items():
            macrolist = []
            for hostname, nagstring in entries.items():
                macrolist.append((nagstring, [hostname]))
            if len(macrolist) > 0:
                self._data.setdefault("custom_macros", {})[custom_varname] = macrolist

    def save_explicit_host_settings(self, explicit_host_settings: Dict[str, Dict[str, str]]):
        for varname, entries in explicit_host_settings.items():
            if len(entries) > 0:
                self._data.setdefault("explicit_host_conf", {})[varname] = entries

    def save_attributes(self, attribute_mappings: List[AttributeType]):
        for _, cmk_base_varname, dictionary, _ in attribute_mappings:
            if dictionary:
                self._data.setdefault("attributes", {})[cmk_base_varname] = dictionary

    def save_contact_groups(self, groups: Tuple[Set[bool], Set[bool], bool]):
        # If the contact groups of the folder are set to be used for the monitoring,
        # we create an according rule for the folder here and an according rule for
        # each host that has an explicit setting for that attribute (see above).
        _permitted_groups, contact_groups, use_for_services = groups
        if contact_groups:
            self._data.setdefault("contact_groups", {})["host_contact_groups"] = {
                "value": contact_groups,
                "condition": {
                    'host_folder': '/%%TODO/'
                }
            }
            if use_for_services:
                # Currently service_contactgroups requires single values. Lists are not supported
                for cg in contact_groups:
                    self._data.setdefault("contact_groups", {})["service_contact_groups"] = {
                        "value": cg,
                        "condition": {
                            'host_folder': '/%%TODO/'
                        }
                    }

    def save_cleaned_hosts(self, cleaned_hosts: Dict[str, Dict[str, Any]]) -> None:
        """Write information about all host attributes into special variable - even
        values stored for check_mk as well."""
        self._data["host_attributes"] = cleaned_hosts


def make_hosts_storage() -> ABCHostsStorage:
    """Factory creates a storage suitable for current distribution.
    The flag will be located, probably in cee.py"""
    return StandardHostsStorage()


def configurable_variables() -> Dict[str, Any]:
    """Returns block of variables which may be changed during config loading"""
    return {
        "FOLDER_PATH": "",
        "ALL_HOSTS": ALL_HOSTS,
        "ALL_SERVICES": ALL_SERVICES,
        "all_hosts": [],
        "host_labels": {},
        "host_tags": {},
        "clusters": {},
        "ipaddresses": {},
        "ipv6addresses": {},
        "explicit_snmp_communities": {},
        "management_snmp_credentials": {},
        "management_ipmi_credentials": {},
        "management_protocol": {},
        "explicit_host_conf": {},
        "extra_host_conf": {
            "alias": []
        },
        "extra_service_conf": {
            "_WATO": []
        },
        "host_attributes": {},
        "host_contactgroups": [],
        "service_contactgroups": [],
        "_lock": False,
    }
