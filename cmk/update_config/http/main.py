#!/usr/bin/env python3
# Copyright (C) 2024 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

import enum
import re
import sys
from collections.abc import Mapping
from contextlib import suppress
from ipaddress import AddressValueError, IPv6Address, NetmaskValueError
from pprint import pprint
from typing import Literal

from pydantic import BaseModel, HttpUrl, ValidationError

from cmk.utils.redis import disable_redis

from cmk.gui.main_modules import load_plugins
from cmk.gui.session import SuperUserContext
from cmk.gui.utils.script_helpers import gui_context
from cmk.gui.watolib.rulesets import AllRulesets
from cmk.gui.wsgi.blueprints.global_vars import set_global_vars


class HostType(enum.Enum):
    IPV6 = enum.auto()
    EMBEDDABLE = enum.auto()
    INVALID = enum.auto()


def _classify(host: str) -> HostType:
    with suppress(ValidationError):
        HttpUrl(url=f"http://{host}")
        return HostType.EMBEDDABLE
    with suppress(AddressValueError, NetmaskValueError):
        IPv6Address(host)
        return HostType.IPV6
    return HostType.INVALID


class V1Proxy(BaseModel, extra="forbid"):
    address: str
    port: int | None = None
    # auth: None  # TODO: This is not supported in V2. Turn into conflict?


class V1Host(BaseModel, extra="forbid"):
    address: tuple[Literal["direct"], str] | tuple[Literal["proxy"], V1Proxy]
    address_family: Literal["any", "ipv4_enforced", "ipv6_enforced", "primary_enforced", None] = (
        None
    )
    # If this field is unspecified, it will set depending on the `virtual host`, if check_cert is
    # true, if client_cert is true, client private key or -S is enabled. On redirect new ports might
    # be defined. This behaviour will not transfer to the new check, most likely.
    port: int | None = None
    # TODO: The URL always needs to point to the physical server, with a client optionally providing
    # a different destination in the HostName header, as far as I understand. This is implemented
    # correctly in check_http.c (v1). The v1 ssc behaves very strangely, since it uses HTTP 1.0, if
    # no virtual host is specified (instead of deducing the HostName from the physical server name).
    # In v2, the implementation is also strange, since it demands the virtual host, and makes the
    # physical server optional. This needs to be discussed with PM.
    # What should really happen:
    # url: contains server, that needs to be DNS resolved (given always by address field in v1)
    # host name header: contains the virtual host
    virthost: None = None


class V1Auth(BaseModel, extra="forbid"):
    user: str
    password: object


class V1Regex(BaseModel, extra="forbid"):
    regex: str
    case_insensitive: bool
    crit_if_found: bool
    multiline: bool


class V1PostData(BaseModel, extra="forbid"):
    data: str
    content_type: str


class V1PageSize(BaseModel, extra="forbid"):
    minimum: int
    maximum: int


SimpleLevelsFloat = tuple[Literal["fixed"], tuple[float, float]] | tuple[Literal["no_levels"], None]


class V1Cert(BaseModel, extra="forbid"):
    cert_days: SimpleLevelsFloat


class V1Url(BaseModel, extra="forbid"):
    uri: str | None = None  # TODO: passed via -u in V1, unclear whether this is the same as V2.
    ssl: (
        Literal[
            "auto",  # use with auto-negotiation
            "ssl_1_2",  # enforce TLS 1.2
            "ssl_1_3",  # enforce TLS 1.3
            # "ssl_1",  # enforce TLS 1.0, not supported in V2
            # "ssl_2",  # enforce SSL 2.0, not supported in V2
            # "ssl_3",  # enforce SSL 3.0, not supported in V2
        ]
        | None
    ) = None
    response_time: SimpleLevelsFloat | None = None
    timeout: int | None = None
    user_agent: str | None = None
    add_headers: list[str] | None = None
    auth: V1Auth | None = None
    onredirect: Literal["ok", "warning", "critical", "follow", "sticky", "stickyport"] | None = None
    expect_response_header: str | None = None
    expect_response: list[str] | None = None
    expect_string: str | None = None
    expect_regex: V1Regex | None = None
    post_data: V1PostData | None = None
    method: (
        Literal[
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            # Not supported by V2
            # "OPTIONS", "TRACE", "CONNECT", "CONNECT_POST", "PROPFIND",
        ]
        | None
    ) = None
    no_body: Literal[True, None] = None
    page_size: V1PageSize | None = None
    max_age: int | None = None
    urlize: Literal[True, None] = None
    extended_perfdata: Literal[True, None] = None


class V1Value(BaseModel, extra="forbid"):
    name: str
    host: V1Host
    mode: tuple[Literal["url"], V1Url] | tuple[Literal["cert"], V1Cert]
    disable_sni: Literal[True, None] = None


def _migratable_url_params(url_params: V1Url) -> bool:
    if any(":" not in header for header in url_params.add_headers or []):
        return False
    if (
        url_params.expect_response_header is not None
        and "\r\n" in url_params.expect_response_header.strip("\r\n")
    ):
        # TODO: Redirects behave differently in V1 and V2.
        return False
    if url_params.expect_regex is not None and url_params.expect_string is not None:
        return False
    if url_params.post_data is not None and url_params.method in ("GET", "DELETE", "HEAD"):
        return False
    try:
        _migrate_expect_response(url_params.expect_response or [])
    except ValueError:
        return False
    return True


def _migratable(rule_value: Mapping[str, object]) -> bool:
    try:
        value = V1Value.model_validate(rule_value)
    except ValidationError:
        return False
    address = value.host.address[1]
    if isinstance(address, str):
        type_ = _classify(address)
        if type_ is not HostType.EMBEDDABLE:
            # This might have some issues, since customers can put a port, uri, and really mess with
            # us in a multitude of ways.
            return False
    else:
        type_ = _classify(address.address)
        if type_ is not HostType.EMBEDDABLE:
            # We have the same issue as above.
            return False
        return False  # TODO: We don't have a address, if proxy is specified because of the HOSTADDRESS-url conflict.
    if value.disable_sni:
        return False
    if isinstance(value.mode[1], V1Cert):
        return True
    return _migratable_url_params(value.mode[1])


def _migrate_header(header: str) -> dict[str, object]:
    name, value = header.split(":", 1)
    return {"header_name": name, "header_value": value.strip()}  # TODO: This is not a 1:1 mapping.


def _migrate_expect_response(response: list[str]) -> list[int]:
    result = []
    for item in response:
        if (status := re.search(r"\d{3}", item)) is not None:
            result.append(int(status.group()))
        else:
            raise ValueError(f"Invalid status code: {item}")
    return result


def _migrate_url_params(
    url_params: V1Url, address_family: str
) -> tuple[Literal["http", "https"], str, dict[str, object], Mapping[str, object]]:
    path = url_params.uri or ""
    match url_params.ssl:
        # In check_http.c (v1), this also determines the port.
        # If this logic is adapted, then `_migrate_name` needs to be fixed.
        case None:
            scheme: Literal["http", "https"] = "http"
            tls_versions = {}
        case "auto":
            scheme = "https"
            # TODO: PMs specified allow_higher False, revisit this, once we have their reasoning.
            tls_versions = {"tls_versions": {"min_version": "auto", "allow_higher": True}}
        case "ssl_1_2":
            scheme = "https"
            tls_versions = {"tls_versions": {"min_version": "tls_1_2", "allow_higher": False}}
        case "ssl_1_3":
            scheme = "https"
            tls_versions = {"tls_versions": {"min_version": "tls_1_3", "allow_higher": False}}
    match url_params.response_time:
        case None:
            response_time: Mapping[str, object] = {}
        case levels:
            response_time = {"response_time": levels}
    match url_params.timeout:
        case None:
            timeout: Mapping[str, object] = {}
        case timeout_sec:
            timeout = {"timeout": float(timeout_sec)}
    match url_params.user_agent:
        case None:
            # TODO: This implicitly changes the user agent from `check_http/v2.3.3
            # (monitoring-plugins 2.3.3)` to `checkmk-active-httpv2/2.4.0`
            user_agent: Mapping[str, object] = {}
        case agent:
            user_agent = {"user_agent": agent}
    match url_params.add_headers:
        case None:
            add_headers: Mapping[str, object] = {}
        case headers:
            add_headers = {"add_headers": [_migrate_header(header) for header in headers]}
    match url_params.auth:
        case None:
            auth: Mapping[str, object] = {}
        case user_auth:
            auth = {"auth": ("user_auth", user_auth.model_dump())}
    match url_params.expect_response_header:
        case None:
            content_header: Mapping[str, object] = {}
        case expect_response_header:
            content_header = {
                "header": ("string", _migrate_header(expect_response_header.strip("\r\n")))
            }
    match url_params.expect_response:
        case None:
            server_response: Mapping[str, object] = {}
        case expect_response:
            server_response = {
                "server_response": {"expected": _migrate_expect_response(expect_response)}
            }
    match url_params.onredirect:
        # TODO: V1 and V2 work differently, if searching for strings in documents, also need to test
        # with http codes.
        case None:
            redirects: Mapping[str, object] = {}
        case onredirect:
            redirects = {"redirects": onredirect}
    match url_params.expect_string, url_params.expect_regex:
        case None, None:
            body: Mapping[str, object] = {}
        case expect_string, None:
            assert expect_string is not None
            body = {"body": ("string", expect_string)}
        case None, expect_regex:
            assert expect_regex is not None
            body = {
                "body": (
                    "regex",
                    {
                        "regex": expect_regex.regex,
                        "case_insensitive": expect_regex.case_insensitive,
                        "multiline": expect_regex.multiline,
                        "invert": expect_regex.crit_if_found,
                    },
                )
            }
        case _, _:
            raise NotImplementedError()
    match url_params.method, url_params.post_data:
        case None, None:
            method: Mapping[str, object] = {"method": ("get", None)}
        case "GET", None:
            method = {"method": ("get", None)}
        case "HEAD", None:
            method = {"method": ("head", None)}
        case "DELETE", None:
            method = {"method": ("delete", None)}
        case "POST" | "PUT" | None, post_data:
            method_type = {
                "POST": "post",
                "PUT": "put",
                None: "post",  # TODO: Is this truly the default?
            }[url_params.method]
            send_data = (
                {}
                if post_data is None
                else {
                    "send_data": {
                        "content": post_data.data,
                        "content_type": ("custom", post_data.content_type),
                    }
                }
            )
            method = {"method": (method_type, send_data)}
    match url_params.no_body:
        case None:
            document_body: Mapping[str, object] = {"document_body": "fetch"}
        case True:
            # TODO: What happens to the searching document bodies here?
            document_body = {"document_body": "ignore"}
    match url_params.page_size:
        case None:
            page_size_new: Mapping[str, object] = {}
        case page_size:
            page_size_new = {"page_size": {"min": page_size.minimum, "max": page_size.maximum}}
    match url_params.max_age:
        case None:
            max_age_new: Mapping[str, object] = {}
        case max_age:
            max_age_new = {"max_age": max_age}
    return (
        scheme,
        path,
        {
            **method,  # TODO: Proxy sets this to CONNECT.
            **tls_versions,
            **timeout,
            **user_agent,
            **add_headers,
            **auth,
            **redirects,
            "address_family": address_family,
        },
        {
            **server_response,
            **response_time,
            "content": {
                **content_header,
                **body,
            },
            "document": {
                **document_body,
                **page_size_new,
                **max_age_new,
            },
        },
    )


def _migrate_cert_params(
    cert_params: V1Cert, address_family: str
) -> tuple[dict[str, object], Mapping[str, object]]:
    return (
        {
            "method": ("get", None),
            "address_family": address_family,
        },
        {
            "cert": ("validate", cert_params.cert_days),
        },
    )


def _migrate_name(name: str) -> Mapping[str, object]:
    # Currently, this implementation is consistent with V1.
    if name.startswith("^"):
        return {"prefix": "none", "name": name[1:]}
    return {"prefix": "auto", "name": name}


def _build_url(scheme: str, host: str, port: int | None, path: str) -> str:
    port_suffix = f":{port}" if port is not None else ""
    return f"{scheme}://{host}{port_suffix}{path}"


def _migrate(rule_value: V1Value) -> Mapping[str, object]:
    match rule_value.host.address_family:
        case "any":
            address_family = "any"
        case "ipv4_enforced":
            address_family = "ipv4"
        case "ipv6_enforced":
            address_family = "ipv6"
        case "primary_enforced":
            address_family = "primary"
        case None:
            address_family = "any"
    if isinstance(rule_value.mode[1], V1Cert):
        scheme, path, connection, remaining_settings = (
            "https",
            "",
            *_migrate_cert_params(rule_value.mode[1], address_family),
        )
    else:
        scheme, path, connection, remaining_settings = _migrate_url_params(
            rule_value.mode[1], address_family
        )

    address = rule_value.host.address[1]
    if isinstance(address, str):
        url = _build_url(scheme, address, rule_value.host.port, path)
    else:
        proxy = _build_url(scheme, address.address, address.port or rule_value.host.port, path)
        connection["proxy"] = proxy

    return {
        "endpoints": [
            {
                "service_name": _migrate_name(name=rule_value.name),
                # Risk: We can't be sure the active checks and the config cache use the same IP look
                # up (but both of them are based on the same user data. Moreover,
                # `primary_ip_config.address` (see `get_ssc_host_config` is slightly differently
                # implemented than `HOSTADDRESS` (see `attrs["address"]` in
                # `cmk/base/config.py:3454`).
                "url": url,
                "individual_settings": {
                    "connection": connection,
                    **remaining_settings,
                },
            },
        ],
    }


def main() -> None:
    load_plugins()
    with disable_redis(), gui_context(), SuperUserContext():
        set_global_vars()
        all_rulesets = AllRulesets.load_all_rulesets()
    for folder, rule_index, rule in all_rulesets.get_rulesets()["active_checks:http"].get_rules():
        if _migratable(rule.value):
            sys.stdout.write(f"MIGRATABLE: {folder}, {rule_index}\n")
        else:
            sys.stdout.write(f"IMPOSSIBLE: {folder}, {rule_index}\n")
        pprint(rule.value)  # nosemgrep: disallow-print
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
