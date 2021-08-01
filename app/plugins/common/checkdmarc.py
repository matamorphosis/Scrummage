#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validates and parses SPF amd DMARC DNS records"""

import logging
from collections import OrderedDict
from re import compile, IGNORECASE
import json
from csv import DictWriter
from argparse import ArgumentParser
import os
from time import sleep
from datetime import datetime, timedelta
import socket
import smtplib
import tempfile
import platform
import shutil
import atexit
import requests
from ssl import SSLError, CertificateError, create_default_context

from io import StringIO
from expiringdict import ExpiringDict

import publicsuffix2
import dns
import dns.resolver
import dns.exception
import timeout_decorator
from pyleri import (Grammar,
                    Regex,
                    Sequence,
                    List,
                    Repeat
                    )
import ipaddress

"""Copyright 2019 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

__version__ = "4.4.1"

DMARC_VERSION_REGEX_STRING = r"v=DMARC1;"
BIMI_VERSION_REGEX_STRING = r"v=BIMI1;"
DMARC_TAG_VALUE_REGEX_STRING = r"([a-z]{1,5})=([\w.:@/+!,_\- ]+)"
BIMI_TAG_VALUE_REGEX_STRING = r"([a-z]{1})=(.*)"
MAILTO_REGEX_STRING = r"^(mailto):" \
                      r"([\w\-!#$%&'*+-/=?^_`{|}~]" \
                      r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?"
SPF_VERSION_TAG_REGEX_STRING = "v=spf1"
SPF_MECHANISM_REGEX_STRING = r"([+\-~?])?(mx|ip4|ip6|exists|include|all|a|" \
                             r"redirect|exp|ptr)[:=]?([\w+/_.:\-{%}]*)"
AFTER_ALL_REGEX_STRING = "all .*"

DMARC_TAG_VALUE_REGEX = compile(DMARC_TAG_VALUE_REGEX_STRING)
BIMI_TAG_VALUE_REGEX = compile(BIMI_TAG_VALUE_REGEX_STRING)
MAILTO_REGEX = compile(MAILTO_REGEX_STRING)
SPF_MECHANISM_REGEX = compile(SPF_MECHANISM_REGEX_STRING, IGNORECASE)
AFTER_ALL_REGEX = compile(AFTER_ALL_REGEX_STRING, IGNORECASE)

USER_AGENT = "Mozilla/5.0 (({0} {1})) parsedmarc/{2}".format(
            platform.system(),
            platform.release(),
            __version__
        )

DNS_CACHE = ExpiringDict(max_len=200000, max_age_seconds=1800)
TLS_CACHE = ExpiringDict(max_len=200000, max_age_seconds=1800)
STARTTLS_CACHE = ExpiringDict(max_len=200000, max_age_seconds=1800)

TMPDIR = tempfile.mkdtemp()


def _cleanup():
    """Remove temporary files"""
    shutil.rmtree(TMPDIR)


atexit.register(_cleanup)


class SMTPError(Exception):
    """Raised when n SMTP error occurs"""


class SPFError(Exception):
    """Raised when a fatal SPF error occurs"""
    def __init__(self, msg, data=None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the output
        """
        self.data = data
        Exception.__init__(self, msg)


class _SPFWarning(Exception):
    """Raised when a non-fatal SPF error occurs"""


class _SPFMissingRecords(_SPFWarning):
    """Raised when a mechanism in a ``SPF`` record is missing the requested
    A/AAAA or MX records"""


class _SPFDuplicateInclude(_SPFWarning):
    """Raised when a duplicate SPF include is found"""


class _DMARCWarning(Exception):
    """Raised when a non-fatal DMARC error occurs"""


class _BIMIWarning(Exception):
    """Raised when a non-fatal BIMI error occurs"""


class _DMARCBestPracticeWarning(_DMARCWarning):
    """Raised when a DMARC record does not follow a best practice"""


class DNSException(Exception):
    """Raised when a general DNS error occurs"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DMARCError(Exception):
    """Raised when a fatal DMARC error occurs"""
    def __init__(self, msg, data=None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class SPFRecordNotFound(SPFError):
    """Raised when an SPF record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class MultipleSPFRTXTRecords(SPFError):
    """Raised when multiple TXT spf1 records are found"""


class SPFSyntaxError(SPFError):
    """Raised when an SPF syntax error is found"""


class SPFTooManyDNSLookups(SPFError):
    """Raised when an SPF record requires too many DNS lookups (10 max)"""
    def __init__(self, *args, **kwargs):
        data = dict(dns_lookups=kwargs["dns_lookups"])
        SPFError.__init__(self, args[0], data=data)


class SPFRedirectLoop(SPFError):
    """Raised when a SPF redirect loop is detected"""


class SPFIncludeLoop(SPFError):
    """Raised when a SPF include loop is detected"""


class DMARCRecordNotFound(DMARCError):
    """Raised when a DMARC record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DMARCSyntaxError(DMARCError):
    """Raised when a DMARC syntax error is found"""


class InvalidDMARCTag(DMARCSyntaxError):
    """Raised when an invalid DMARC tag is found"""


class InvalidDMARCTagValue(DMARCSyntaxError):
    """Raised when an invalid DMARC tag value is found"""


class InvalidDMARCReportURI(InvalidDMARCTagValue):
    """Raised when an invalid DMARC reporting URI is found"""


class UnrelatedTXTRecordFoundAtDMARC(DMARCError):
    """Raised when a TXT record unrelated to DMARC is found"""


class SPFRecordFoundWhereDMARCRecordShouldBe(UnrelatedTXTRecordFoundAtDMARC):
    """Raised when a SPF record is found where a DMARC record should be;
    most likely, the ``_dmarc`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class DMARCRecordInWrongLocation(DMARCError):
    """Raised when a DMARC record is found at the root of a domain"""


class DMARCReportEmailAddressMissingMXRecords(_DMARCWarning):
    """Raised when a email address in a DMARC report URI is missing MX
    records"""


class UnverifiedDMARCURIDestination(_DMARCWarning):
    """Raised when the destination of a DMARC report URI does not indicate
    that it accepts reports for the domain"""


class MultipleDMARCRecords(DMARCError):
    """Raised when multiple DMARC records are found, in violation of
    RFC 7486, section 6.6.3"""


class BIMIError(Exception):
    """Raised when a fatal BIMI error occurs"""
    def __init__(self, msg, data=None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class BIMIRecordNotFound(BIMIError):
    """Raised when a BIMI record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class BIMISyntaxError(BIMIError):
    """Raised when a BIMI syntax error is found"""


class InvalidBIMITag(BIMISyntaxError):
    """Raised when an invalid BIMI tag is found"""


class InvalidBIMITagValue(BIMISyntaxError):
    """Raised when an invalid BIMI tag value is found"""


class InvalidBIMIIndicatorURI(InvalidBIMITagValue):
    """Raised when an invalid BIMI indicator URI is found"""


class UnrelatedTXTRecordFoundAtBIMI(BIMIError):
    """Raised when a TXT record unrelated to BIMI is found"""


class SPFRecordFoundWhereBIMIRecordShouldBe(UnrelatedTXTRecordFoundAtBIMI):
    """Raised when a SPF record is found where a BIMI record should be;
    most likely, the ``selector_bimi`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class BIMIRecordInWrongLocation(BIMIError):
    """Raised when a BIMI record is found at the root of a domain"""


class MultipleBIMIRecords(BIMIError):
    """Raised when multiple BIMI records are found"""


class _SPFGrammar(Grammar):
    """Defines Pyleri grammar for SPF records"""
    version_tag = Regex(SPF_VERSION_TAG_REGEX_STRING)
    mechanism = Regex(SPF_MECHANISM_REGEX_STRING, IGNORECASE)
    START = Sequence(version_tag, Repeat(mechanism))


class _DMARCGrammar(Grammar):
    """Defines Pyleri grammar for DMARC records"""
    version_tag = Regex(DMARC_VERSION_REGEX_STRING)
    tag_value = Regex(DMARC_TAG_VALUE_REGEX_STRING)
    START = Sequence(version_tag, List(tag_value, delimiter=";", opt=True))


class _BIMIGrammar(Grammar):
    """Defines Pyleri grammar for BIMI records"""
    version_tag = Regex(BIMI_VERSION_REGEX_STRING)
    tag_value = Regex(BIMI_TAG_VALUE_REGEX_STRING)
    START = Sequence(version_tag, List(tag_value, delimiter=";", opt=True))


tag_values = OrderedDict(adkim=OrderedDict(name="DKIM Alignment Mode",
                                           default="r",
                                           description='In relaxed mode, '
                                                       'the Organizational '
                                                       'Domains of both the '
                                                       'DKIM-authenticated '
                                                       'signing domain (taken '
                                                       'from the value of the '
                                                       '"d=" tag in the '
                                                       'signature) and that '
                                                       'of the RFC 5322 '
                                                       'From domain '
                                                       'must be equal if the '
                                                       'identifiers are to be '
                                                       'considered aligned.'),
                         aspf=OrderedDict(name="SPF alignment mode",
                                          default="r",
                                          description='In relaxed mode, '
                                                      'the SPF-authenticated '
                                                      'domain and RFC5322 '
                                                      'From domain must have '
                                                      'the same '
                                                      'Organizational Domain. '
                                                      'In strict mode, only '
                                                      'an exact DNS domain '
                                                      'match is considered to '
                                                      'produce Identifier '
                                                      'Alignment.'),
                         fo=OrderedDict(name="Failure Reporting Options",
                                        default="0",
                                        description='Provides requested '
                                                    'options for generation '
                                                    'of failure reports. '
                                                    'Report generators MAY '
                                                    'choose to adhere to the '
                                                    'requested options. '
                                                    'This tag\'s content '
                                                    'MUST be ignored if '
                                                    'a "ruf" tag (below) is '
                                                    'not also specified. '
                                                    'The value of this tag is '
                                                    'a colon-separated list '
                                                    'of characters that '
                                                    'indicate failure '
                                                    'reporting options.',
                                        values={
                                            "0": 'Generate a DMARC failure '
                                                 'report if all underlying '
                                                 'authentication mechanisms '
                                                 'fail to produce an aligned '
                                                 '"pass" result.',
                                            "1": 'Generate a DMARC failure '
                                                 'report if any underlying '
                                                 'authentication mechanism '
                                                 'produced something other '
                                                 'than an aligned '
                                                 '"pass" result.',
                                            "d": 'Generate a DKIM failure '
                                                 'report if the message had '
                                                 'a signature that failed '
                                                 'evaluation, regardless of '
                                                 'its alignment. DKIM-'
                                                 'specific reporting is '
                                                 'described in AFRF-DKIM.',
                                            "s": 'Generate an SPF failure '
                                                 'report if the message '
                                                 'failed SPF evaluation, '
                                                 'regardless of its alignment.'
                                                 ' SPF-specific reporting is '
                                                 'described in AFRF-SPF'
                                            }
                                        ),
                         p=OrderedDict(name="Requested Mail Receiver Policy",
                                       description='Specifies the policy to '
                                                   'be enacted by the '
                                                   'Receiver at the '
                                                   'request of the '
                                                   'Domain Owner. The '
                                                   'policy applies to '
                                                   'the domain and to its '
                                                   'subdomains, unless '
                                                   'subdomain policy '
                                                   'is explicitly described '
                                                   'using the "sp" tag.',
                                       values={
                                           "none": 'The Domain Owner requests '
                                                   'no specific action be '
                                                   'taken regarding delivery '
                                                   'of messages.',
                                           "quarantine": 'The Domain Owner '
                                                         'wishes to have '
                                                         'email that fails '
                                                         'the DMARC mechanism '
                                                         'check be treated by '
                                                         'Mail Receivers as '
                                                         'suspicious. '
                                                         'Depending on the '
                                                         'capabilities of the '
                                                         'MailReceiver, '
                                                         'this can mean '
                                                         '"place into spam '
                                                         'folder", '
                                                         '"scrutinize '
                                                         'with additional '
                                                         'intensity", and/or '
                                                         '"flag as '
                                                         'suspicious".',
                                           "reject": 'The Domain Owner wishes '
                                                     'for Mail Receivers to '
                                                     'reject '
                                                     'email that fails the '
                                                     'DMARC mechanism check. '
                                                     'Rejection SHOULD '
                                                     'occur during the SMTP '
                                                     'transaction.'
                                           }
                                       ),
                         pct=OrderedDict(name="Percentage",
                                         default=100,
                                         description='Integer percentage of '
                                                     'messages from the '
                                                     'Domain Owner\'s '
                                                     'mail stream to which '
                                                     'the DMARC policy is to '
                                                     'be applied. '
                                                     'However, this '
                                                     'MUST NOT be applied to '
                                                     'the DMARC-generated '
                                                     'reports, all of which '
                                                     'must be sent and '
                                                     'received unhindered. '
                                                     'The purpose of the '
                                                     '"pct" tag is to allow '
                                                     'Domain Owners to enact '
                                                     'a slow rollout of '
                                                     'enforcement of the '
                                                     'DMARC mechanism.'
                                         ),
                         rf=OrderedDict(name="Report Format",
                                        default="afrf",
                                        description='A list separated by '
                                                    'colons of one or more '
                                                    'report formats as '
                                                    'requested by the '
                                                    'Domain Owner to be '
                                                    'used when a message '
                                                    'fails both SPF and DKIM '
                                                    'tests to report details '
                                                    'of the individual '
                                                    'failure. Only "afrf" '
                                                    '(the auth-failure report '
                                                    'type) is currently '
                                                    'supported in the '
                                                    'DMARC standard.',
                                        values={
                                            "afrf": ' "Authentication Failure '
                                                    'Reporting Using the '
                                                    'Abuse Reporting Format", '
                                                    'RFC 6591, April 2012,'
                                                    '<http://www.rfc-'
                                                    'editor.org/info/rfc6591>'
                                        }
                                        ),
                         ri=OrderedDict(name="Report Interval",
                                        default=86400,
                                        description='Indicates a request to '
                                                    'Receivers to generate '
                                                    'aggregate reports '
                                                    'separated by no more '
                                                    'than the requested '
                                                    'number of seconds. '
                                                    'DMARC implementations '
                                                    'MUST be able to provide '
                                                    'daily reports and '
                                                    'SHOULD be able to '
                                                    'provide hourly reports '
                                                    'when requested. '
                                                    'However, anything other '
                                                    'than a daily report is '
                                                    'understood to '
                                                    'be accommodated on a '
                                                    'best-effort basis.'
                                        ),
                         rua=OrderedDict(name="Aggregate Feedback Addresses",
                                         description=' A comma-separated list '
                                                     'of DMARC URIs to which '
                                                     'aggregate feedback '
                                                     'is to be sent.'
                                         ),
                         ruf=OrderedDict(name="Forensic Feedback Addresses",
                                         description=' A comma-separated list '
                                                     'of DMARC URIs to which '
                                                     'forensic feedback '
                                                     'is to be sent.'
                                         ),
                         sp=OrderedDict(name="Subdomain Policy",
                                        description='Indicates the policy to '
                                                    'be enacted by the '
                                                    'Receiver at the request '
                                                    'of the Domain Owner. '
                                                    'It applies only to '
                                                    'subdomains of the '
                                                    'domain queried, and not '
                                                    'to the domain itself. '
                                                    'Its syntax is identical '
                                                    'to that of the "p" tag '
                                                    'defined above. If '
                                                    'absent, the policy '
                                                    'specified by the "p" '
                                                    'tag MUST be applied '
                                                    'for subdomains.'
                                        ),
                         v=OrderedDict(name="Version",
                                       description='Identifies the record '
                                                   'retrieved as a DMARC '
                                                   'record. It MUST have the '
                                                   'value of "DMARC1". The '
                                                   'value of this tag MUST '
                                                   'match precisely; if it '
                                                   'does not or it is absent, '
                                                   'the entire retrieved '
                                                   'record MUST be ignored. '
                                                   'It MUST be the first '
                                                   'tag in the list.')
                         )

spf_qualifiers = {
    "": "pass",
    "?": "neutral",
    "+": "pass",
    "-": "fail",
    "~": "softfail"
}


bimi_tags = OrderedDict(
    v=OrderedDict(name="Version",
                  description='Identifies the record '
                              'retrieved as a BIMI '
                              'record. It MUST have the '
                              'value of "BIMI1". The '
                              'value of this tag MUST '
                              'match precisely; if it '
                              'does not or it is absent, '
                              'the entire retrieved '
                              'record MUST be ignored. '
                              'It MUST be the first '
                              'tag in the list.')
)


def get_base_domain(domain, use_fresh_psl=False):
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat.

    Args:
        domain (str): A domain or subdomain
        use_fresh_psl (bool): Download a fresh Public Suffix List

    Returns:
        str: The base domain of the given domain

    """
    psl_path = os.path.join(TMPDIR, "public_suffix_list.dat")

    def download_psl():
        url = "https://publicsuffix.org/list/public_suffix_list.dat"
        # Use a browser-like user agent string to bypass some proxy blocks
        headers = {"User-Agent": USER_AGENT}
        fresh_psl = requests.get(url, headers=headers).text
        with open(psl_path, "w", encoding="utf-8") as fresh_psl_file:
            fresh_psl_file.write(fresh_psl)

    domain = domain.lower()
    if domain.endswith(".test") or domain.endswith(
            ".example") or domain.endswith(".invalid") or domain.endswith(
           ".localhost"):
        parts = domain.strip(".").split(".")
        if len(parts) == 1:
            return parts[0]
        else:
            return ".".join(parts[-2::])
    if use_fresh_psl:
        if not os.path.exists(psl_path):
            download_psl()
        else:
            psl_age = datetime.now() - datetime.fromtimestamp(
                os.stat(psl_path).st_mtime)
            if psl_age > timedelta(hours=24):
                try:
                    download_psl()
                except Exception as error:
                    logging.warning(
                        "Failed to download an updated PSL {0}".format(error))
        with open(psl_path, encoding="utf-8") as psl_file:
            psl = publicsuffix2.PublicSuffixList(psl_file)

        return psl.get_public_suffix(domain)
    else:
        return publicsuffix2.get_sld(domain)


def _query_dns(domain, record_type, nameservers=None, timeout=2.0,
               cache=None):
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        nameservers (list): A list of one or more nameservers to use
        timeout (float): Sets the DNS timeout in seconds
        cache (ExpiringDict): Cache storage

    Returns:
        list: A list of answers
    """
    domain = str(domain).lower()
    record_type = record_type.upper()
    cache_key = "{0}_{1}".format(domain, record_type)
    if cache is None:
        cache = DNS_CACHE
    if cache:
        records = cache.get(cache_key, None)
        if records:
            return records

    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers is not None:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if record_type == "TXT":
        resource_records = list(map(
            lambda r: r.strings,
            resolver.resolve(domain, record_type, lifetime=timeout)))
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records if resource_record]
        records = [r.decode() for r in _resource_record]
    else:
        records = list(map(
            lambda r: r.to_text().replace('"', '').rstrip("."),
            resolver.resolve(domain, record_type, lifetime=timeout)))
    if cache:
        cache[cache_key] = records

    return records


def _get_nameservers(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a list of nameservers

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query

    Returns:
        list: A list of ``OrderedDicts``; each containing a ``preference``
                        integer and a ``hostname``

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    answers = []
    try:

        answers = _query_dns(domain, "NS", nameservers=nameservers,
                             timeout=timeout)
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        pass
    except Exception as error:
        raise DNSException(error)
    return answers


def _get_mx_hosts(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a list of Mail Exchange hosts

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query

    Returns:
        list: A list of ``OrderedDicts``; each containing a ``preference``
                        integer and a ``hostname``

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    hosts = []
    try:
        logging.debug("Checking for MX records on {0}".format(domain))
        answers = _query_dns(domain, "MX", nameservers=nameservers,
                             timeout=timeout)
        for record in answers:
            record = record.split(" ")
            preference = int(record[0])
            hostname = record[1].rstrip(".").strip().lower()
            hosts.append(OrderedDict(
                [("preference", preference), ("hostname", hostname)]))
        hosts = sorted(hosts, key=lambda h: (h["preference"], h["hostname"]))
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        pass
    except Exception as error:
        raise DNSException(error)
    return hosts


def _get_a_records(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for A and AAAA records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A sorted list of IPv4 and IPv6 addresses

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    qtypes = ["A", "AAAA"]
    addresses = []
    for qt in qtypes:
        try:
            addresses += _query_dns(domain, qt, nameservers=nameservers,
                                    timeout=timeout)
        except dns.resolver.NXDOMAIN:
            raise DNSException("The domain {0} does not exist".format(domain))
        except dns.resolver.NoAnswer:
            # Sometimes a domain will only have A or AAAA records, but not both
            pass
        except Exception as error:
            raise DNSException(error)

    addresses = sorted(addresses)
    return addresses


def _get_reverse_dns(ip_address, nameservers=None, timeout=2.0):
    """
    Queries for an IP addresses reverse DNS hostname(s)

    Args:
        ip_address (str): An IPv4 or IPv6 address

    Returns:
        list: A list of reverse DNS hostnames
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        name = dns.reversename.from_address(ip_address)
        hostnames = _query_dns(name, "PTR", nameservers=nameservers,
                               timeout=timeout)
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as error:
        raise DNSException(error)

    return hostnames


def _get_txt_records(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for TXT records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of TXT records

     Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        records = _query_dns(domain, "TXT", nameservers=nameservers,
                             timeout=timeout)
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        raise DNSException(
            "The domain {0} does not have any TXT records".format(domain))
    except Exception as error:
        raise DNSException(error)

    return records


def _query_dmarc_record(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an record from DNS

    Returns:
        str: A record string or None
    """
    target = "_dmarc.{0}".format(domain.lower())
    dmarc_record = None
    dmarc_record_count = 0
    unrelated_records = []

    try:
        records = _query_dns(target, "TXT", nameservers=nameservers,
                             timeout=timeout)
        for record in records:
            if record.startswith("v=DMARC1"):
                dmarc_record_count += 1
            else:
                unrelated_records.append(record)

        if dmarc_record_count > 1:
            raise MultipleDMARCRecords(
                "Multiple DMARC policy records are not permitted - "
                "https://tools.ietf.org/html/rfc7489#section-6.6.3")
        if len(unrelated_records) > 0:
            raise UnrelatedTXTRecordFoundAtDMARC(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                "at {0}\n\n{1}".format(target, "\n\n".join(unrelated_records)))
        dmarc_record = records[0]

    except dns.resolver.NoAnswer:
        try:
            records = _query_dns(domain.lower(), "TXT",
                                 nameservers=nameservers,
                                 timeout=timeout)
            for record in records:
                if record.startswith("v=DMARC1"):
                    raise DMARCRecordInWrongLocation(
                        "The DMARC record must be located at "
                        "{0}, not {1}".format(target, domain.lower()))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise DMARCRecordNotFound(
                "The domain {0} does not exist".format(domain))
        except Exception as error:
            DMARCRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as error:
        raise DMARCRecordNotFound(error)

    return dmarc_record


def _query_bmi_record(domain, selector="default", nameservers=None,
                      timeout=2.0):
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector: the BIMI selector
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an record from DNS

    Returns:
        str: A record string or None
    """
    target = "{0}._bimi.{1}".format(selector, domain.lower())
    bimi_record = None
    bmi_record_count = 0
    unrelated_records = []

    try:
        records = _query_dns(target, "TXT", nameservers=nameservers,
                             timeout=timeout)
        for record in records:
            if record.startswith("v=BIMI1"):
                bmi_record_count += 1
            else:
                unrelated_records.append(record)

        if bmi_record_count > 1:
            raise MultipleBIMIRecords(
                "Multiple BMI records are not permitted")
        if len(unrelated_records) > 0:
            raise UnrelatedTXTRecordFoundAtDMARC(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                "at {0}\n\n{1}".format(target, "\n\n".join(unrelated_records)))
        bimi_record = records[0]

    except dns.resolver.NoAnswer:
        try:
            records = _query_dns(domain.lower(), "TXT",
                                 nameservers=nameservers,
                                 timeout=timeout)
            for record in records:
                if record.startswith("v=BIMI1"):
                    raise BIMIRecordInWrongLocation(
                        "The BIMI record must be located at "
                        "{0}, not {1}".format(target, domain.lower()))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise BIMIRecordNotFound(
                "The domain {0} does not exist".format(domain))
        except Exception as error:
            BIMIRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as error:
        raise BIMIRecordNotFound(error)

    return bimi_record


def query_dmarc_record(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe`

    """
    logging.debug("Checking for a DMARC record on {0}".format(domain))
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain.lower()
    record = _query_dmarc_record(domain, nameservers=nameservers,
                                 timeout=timeout)
    try:
        root_records = _query_dns(domain.lower(), "TXT",
                                  nameservers=nameservers,
                                  timeout=timeout)
        for root_record in root_records:
            if root_record.startswith("v=DMARC1"):
                warnings.append("DMARC record at root of {0} "
                                "has no effect".format(domain.lower()))
    except Exception:
        pass

    if record is None and domain != base_domain:
        record = _query_dmarc_record(base_domain, nameservers=nameservers,
                                     timeout=timeout)
        location = base_domain
    if record is None:
        raise DMARCRecordNotFound(
            "A DMARC record does not exist for this domain or its base domain")

    return OrderedDict([("record", record), ("location", location),
                        ("warnings", warnings)])


def query_bimi_record(domain, selector="default", nameservers=None,
                      timeout=2.0):
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector (str): The BMI selector
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.BIMIRecordNotFound`
        :exc:`checkdmarc.BIMIRecordInWrongLocation`
        :exc:`checkdmarc.MultipleBIMIRecords`

    """
    logging.debug("Checking for a BIMI record on {0}".format(domain))
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain.lower()
    record = _query_bmi_record(domain, selector=selector,
                               nameservers=nameservers, timeout=timeout)
    try:
        root_records = _query_dns(domain.lower(), "TXT",
                                  nameservers=nameservers,
                                  timeout=timeout)
        for root_record in root_records:
            if root_record.startswith("v=BIMI1"):
                warnings.append("BIMI record at root of {0} "
                                "has no effect".format(domain.lower()))
    except Exception:
        pass

    if record is None and domain != base_domain and selector != "default":
        record = _query_bmi_record(base_domain, selector="default",
                                   nameservers=nameservers,
                                   timeout=timeout)
        location = base_domain
    if record is None:
        raise BIMIRecordNotFound(
            "A BIMI record does not exist for this domain or its base domain")

    return OrderedDict([("record", record), ("location", location),
                        ("warnings", warnings)])


def get_dmarc_tag_description(tag, value=None):
    """
    Get the name, default value, and description for a DMARC tag, amd/or a
    description for a tag value

    Args:
        tag (str): A DMARC tag
        value (str): An optional value

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``name`` - the tag name
                     - ``default``- the tag's default value
                     - ``description`` - A description of the tag or value
    """
    name = tag_values[tag]["name"]
    description = tag_values[tag]["description"]
    default = None
    if "default" in tag_values[tag]:
        default = tag_values[tag]["default"]
    if type(value) == str and "values" in tag_values[tag] and value in \
            tag_values[tag]["values"][value]:
        description = tag_values[tag]["values"][value]
    elif type(value) == list and "values" in tag_values[tag]:
        new_description = ""
        for value_value in value:
            if value_value in tag_values[tag]["values"]:
                new_description += "{0}: {1}\n\n".format(value_value,
                                                         tag_values[tag][
                                                             "values"][
                                                             value_value])
        new_description = new_description.strip()
        if new_description != "":
            description = new_description

    return OrderedDict(
        [("name", name), ("default", default), ("description", description)])


def parse_dmarc_report_uri(uri):
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf``) URI

    .. note::
        ``mailto`` is the only reporting URI scheme supported in DMARC1

    Args:
        uri: A DMARC URI

    Returns:
        OrderedDict: An ``OrderedDict`` of the URI's components:
                    - ``scheme``
                    - ``address``
                    - ``size_limit``
    Raises:
        :exc:`checkdmarc.InvalidDMARCReportURI`

    """
    uri = uri.strip()
    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        raise InvalidDMARCReportURI(
            "{0} is not a valid DMARC report URI".format(uri))
    match = mailto_matches[0]
    scheme = match[0]
    email_address = match[1]
    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    return OrderedDict([("scheme", scheme), ("address", email_address),
                        ("size_limit", size_limit)])


def check_wildcard_dmarc_report_authorization(domain,
                                              nameservers=None,
                                              timeout=2.0):
    """
    Checks for a wildcard DMARC report authorization record, e.g.:

    ::

      *._report.example.com IN TXT "v=DMARC1"

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        bool: An indicator of the existence of a valid wildcard DMARC report
        authorization record
    """
    wildcard_target = "*._report._dmarc.{0}".format(domain)
    dmarc_record_count = 0
    unrelated_records = []
    try:
        records = _query_dns(wildcard_target, "TXT",
                             nameservers=nameservers,
                             timeout=timeout)

        for record in records:
            if record.startswith("v=DMARC1"):
                dmarc_record_count += 1
            else:
                unrelated_records.append(record)

        if len(unrelated_records) > 0:
            raise UnrelatedTXTRecordFoundAtDMARC(
                "Unrelated TXT records were discovered. "
                "These should be removed, as some "
                "receivers may not expect to find unrelated TXT records "
                "at {0}\n\n{1}".format(wildcard_target,
                                       "\n\n".join(unrelated_records)))

        if dmarc_record_count < 1:
            return False
    except Exception:
        return False

    return True


def verify_dmarc_report_destination(source_domain, destination_domain,
                                    nameservers=None, timeout=2.0):
    """
      Checks if the report destination accepts reports for the source domain
      per RFC 7489, section 7.1

      Args:
          source_domain (str): The source domain
          destination_domain (str): The destination domain
          nameservers (list): A list of nameservers to query
          timeout (float): number of seconds to wait for an answer from DNS

      Returns:
          bool: Indicates if the report domain accepts reports from the given
          domain

      Raises:
          :exc:`checkdmarc.UnverifiedDMARCURIDestination`
          :exc:`checkdmarc.UnrelatedTXTRecordFound`
      """

    source_domain = source_domain.lower()
    destination_domain = destination_domain.lower()

    if get_base_domain(source_domain) != get_base_domain(destination_domain):
        if check_wildcard_dmarc_report_authorization(destination_domain,
                                                     nameservers=nameservers):
            return True
        target = "{0}._report._dmarc.{1}".format(source_domain,
                                                 destination_domain)
        message = "{0} does not indicate that it accepts DMARC reports " \
                  "about {1} - " \
                  "Authorization record not found: " \
                  '{2} IN TXT "v=DMARC1"'.format(destination_domain,
                                                 source_domain,
                                                 target)
        dmarc_record_count = 0
        unrelated_records = []
        try:
            records = _query_dns(target, "TXT",
                                 nameservers=nameservers,
                                 timeout=timeout)

            for record in records:
                if record.startswith("v=DMARC1"):
                    dmarc_record_count += 1
                else:
                    unrelated_records.append(record)

            if len(unrelated_records) > 0:
                raise UnrelatedTXTRecordFoundAtDMARC(
                    "Unrelated TXT records were discovered. "
                    "These should be removed, as some "
                    "receivers may not expect to find unrelated TXT records "
                    "at {0}\n\n{1}".format(target,
                                           "\n\n".join(unrelated_records)))

            if dmarc_record_count < 1:
                return False
        except Exception:
            raise UnverifiedDMARCURIDestination(message)

    return True


def parse_dmarc_record(record, domain, parked=False,
                       include_tag_descriptions=False,
                       nameservers=None, timeout=2.0):
    """
    Parses a DMARC record

    Args:
        record (str): A DMARC record
        domain (str): The domain where the record is found
        parked (bool): Indicates if a domain is parked
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of DMARC tags

           - ``value`` - The DMARC tag value
           - ``explicit`` - ``bool``: A value is explicitly set
           - ``default`` - The tag's default value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``default`` and ``description`` are only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.DMARCSyntaxError`
        :exc:`checkdmarc.InvalidDMARCTag`
        :exc:`checkdmarc.InvaliddDMARCTagValue`
        :exc:`checkdmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.UnrelatedTXTRecordFound`
        :exc:`checkdmarc.DMARCReportEmailAddressMissingMXRecords`

    """
    logging.debug("Parsing the DMARC record for {0}".format(domain))
    spf_in_dmarc_error_msg = "Found a SPF record where a DMARC record " \
                             "should be; most likely, the _dmarc " \
                             "subdomain record does not actually exist, " \
                             "and the request for TXT records was " \
                             "redirected to the base domain"
    warnings = []
    record = record.strip('"')
    if record.startswith("v=spf1"):
        raise SPFRecordFoundWhereDMARCRecordShouldBe(spf_in_dmarc_error_msg)
    dmarc_syntax_checker = _DMARCGrammar()
    parsed_record = dmarc_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        raise DMARCSyntaxError("Error: Expected {0} at position {1} in: "
                               "{2}".format(" or ".join(expecting),
                                            parsed_record.pos, record))

    pairs = DMARC_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()

    # Find explicit tags
    for pair in pairs:
        tags[pair[0]] = OrderedDict(
            [("value", str(pair[1])), ("explicit", True)])

    # Include implicit tags and their defaults
    for tag in tag_values.keys():
        if tag not in tags and "default" in tag_values[tag]:
            tags[tag] = OrderedDict(
                [("value", tag_values[tag]["default"]), ("explicit", False)])
    if "p" not in tags:
        raise DMARCSyntaxError(
            'The record is missing the required policy ("p") tag')
    if "sp" not in tags:
        tags["sp"] = OrderedDict([("value", tags["p"]["value"]),
                                  ("explicit", False)])
    if list(tags.keys())[1] != "p":
        raise DMARCSyntaxError("the p tag must immediately follow the v tag")
    # Validate tag values
    for tag in tags:
        if tag not in tag_values:
            raise InvalidDMARCTag("{0} is not a valid DMARC tag".format(tag))
        if tag == "fo":
            tags[tag]["value"] = tags[tag]["value"].split(":")
            if "0" in tags[tag]["value"] and "1" in tags[tag]["value"]:
                raise InvalidDMARCTagValue(
                    "fo DMARC tag options 0 and 1 are mutually exclusive")
            for value in tags[tag]["value"]:
                if value not in tag_values[tag]["values"]:
                    raise InvalidDMARCTagValue(
                        "{0} is not a valid option for the DMARC "
                        "fo tag".format(value))
        elif tag == "rf":
            tags[tag]["value"] = tags[tag]["value"].split(":")
            for value in tags[tag]["value"]:
                if value not in tag_values[tag]["values"]:
                    raise InvalidDMARCTagValue(
                        "{0} is not a valid option for the DMARC "
                        "rf tag".format(value))

        elif "values" in tag_values[tag] and tags[tag]["value"] not in \
                tag_values[tag]["values"]:
            raise InvalidDMARCTagValue(
                "Tag {0} must have one of the following values: "
                "{1} - not {2}".format(tag,
                                       ",".join(tag_values[tag]["values"]),
                                       tags[tag]["value"]))

    try:
        tags["pct"]["value"] = int(tags["pct"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue(
            "The value of the pct tag must be an integer")

    try:
        tags["ri"]["value"] = int(tags["ri"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue(
            "The value of the ri tag must be an integer")

    try:
        if "rua" in tags:
            parsed_uris = []
            uris = tags["rua"]["value"].split(",")
            for uri in uris:
                uri = parse_dmarc_report_uri(uri)
                parsed_uris.append(uri)
                email_address = uri["address"]
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain.lower():
                    verify_dmarc_report_destination(domain, email_domain,
                                                    nameservers=nameservers,
                                                    timeout=timeout)
                try:
                    _get_mx_hosts(email_domain, nameservers=nameservers,
                                  timeout=timeout)
                except _DMARCWarning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "The domain for rua email address "
                        "{0} has no MX records".format(
                            email_address)
                    )
                except DNSException as warning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "Failed to retrieve MX records for the domain of "
                        "rua email address "
                        "{0} - {1}".format(email_address, str(warning))
                    )
                tags["rua"]["value"] = parsed_uris
                if len(parsed_uris) > 2:
                    raise _DMARCBestPracticeWarning("Some DMARC reporters "
                                                    "might not send to more "
                                                    "than two rua URIs")
        else:
            raise _DMARCBestPracticeWarning(
                "rua tag (destination for aggregate reports) not found")

    except _DMARCWarning as warning:
        warnings.append(str(warning))

    try:
        if "ruf" in tags.keys():
            parsed_uris = []
            uris = tags["ruf"]["value"].split(",")
            for uri in uris:
                uri = parse_dmarc_report_uri(uri)
                parsed_uris.append(uri)
                email_address = uri["address"]
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain.lower():
                    verify_dmarc_report_destination(domain, email_domain,
                                                    nameservers=nameservers,
                                                    timeout=timeout)
                try:
                    _get_mx_hosts(email_domain, nameservers=nameservers,
                                  timeout=timeout)
                except _SPFWarning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "The domain for ruf email address "
                        "{0} has no MX records".format(
                            email_address)
                    )
                except DNSException as warning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "Failed to retrieve MX records for the domain of "
                        "ruf email address "
                        "{0} - {1}".format(email_address, str(warning))
                    )
                tags["ruf"]["value"] = parsed_uris
                if len(parsed_uris) > 2:
                    raise _DMARCBestPracticeWarning("Some DMARC reporters "
                                                    "might not send to more "
                                                    "than two ruf URIs")

        if tags["pct"]["value"] < 0 or tags["pct"]["value"] > 100:
            raise InvalidDMARCTagValue(
                "pct value must be an integer between 0 and 100")
        elif tags["pct"]["value"] < 100:
            warning_msg = "pct value is less than 100. This leads to " \
                          "inconsistent and unpredictable policy " \
                          "enforcement. Consider using p=none to " \
                          "monitor results instead"
            raise _DMARCBestPracticeWarning(warning_msg)
        if parked and tags["p"] != "reject":
            warning_msg = "Policy (p=) should be reject for parked domains"
            raise _DMARCBestPracticeWarning(warning_msg)
        if parked and tags["sp"] != "reject":
            warning_msg = "Subdomain policy (sp=) should be reject for " \
                          "parked domains"
            raise _DMARCBestPracticeWarning(warning_msg)
    except _DMARCWarning as warning:
        warnings.append(str(warning))

    # Add descriptions if requested
    if include_tag_descriptions:
        for tag in tags:
            details = get_dmarc_tag_description(tag, tags[tag]["value"])
            tags[tag]["name"] = details["name"]
            if details["default"]:
                tags[tag]["default"] = details["default"]
            tags[tag]["description"] = details["description"]

    return OrderedDict([("tags", tags), ("warnings", warnings)])


def get_dmarc_record(domain, include_tag_descriptions=False, nameservers=None,
                     timeout=2.0):
    """
    Retrieves a DMARC record for a domain and parses it

    Args:
        domain (str): A domain name
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``record`` - The DMARC record string
         - ``location`` -  Where the DMARC was found
         - ``parsed`` - See :meth:`checkdmarc.parse_dmarc_record`

     Raises:
        :exc:`checkdmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe`
        :exc:`checkdmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.DMARCSyntaxError`
        :exc:`checkdmarc.InvalidDMARCTag`
        :exc:`checkdmarc.InvalidDMARCTagValue`
        :exc:`checkdmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.UnrelatedTXTRecordFound`
        :exc:`checkdmarc.DMARCReportEmailAddressMissingMXRecords`
    """
    query = query_dmarc_record(domain, nameservers=nameservers,
                               timeout=timeout)

    tag_descriptions = include_tag_descriptions

    tags = parse_dmarc_record(query["record"], query["location"],
                              include_tag_descriptions=tag_descriptions,
                              nameservers=nameservers, timeout=timeout)

    return OrderedDict([("record",
                         query["record"]),
                        ("location", query["location"]),
                        ("parsed", tags)])


def query_spf_record(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``record`` - The SPF record string
         - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.SPFRecordNotFound`
    """
    logging.debug("Checking for a SPF record on {0}".format(domain))
    warnings = []
    spf_type_records = []
    spf_txt_records = []
    try:
        spf_type_records += _query_dns(domain, "SPF", nameservers=nameservers,
                                       timeout=timeout)
    except (dns.resolver.NoAnswer, Exception):
        pass

    if len(spf_type_records) > 0:
        message = "SPF type DNS records found. Use of DNS Type SPF has been " \
                  "removed in the standards " \
                  "track version of SPF, RFC 7208. These records should " \
                  "be removed and replaced with TXT records: " \
                  "{0}".format(",".join(spf_type_records))
        warnings.append(message)
    warnings_str = ""
    if len(warnings) > 0:
        warnings_str = ". {0}".format(" ".join(warnings))
    try:
        answers = _query_dns(domain, "TXT", nameservers=nameservers,
                             timeout=timeout)
        spf_record = None
        for record in answers:
            if record.startswith("v=spf1"):
                spf_txt_records.append(record)
        if len(spf_txt_records) > 1:
            raise MultipleSPFRTXTRecords(
                "{0} has multiple SPF TXT records{1}".format(
                    domain, warnings_str))
        elif len(spf_txt_records) == 1:
            spf_record = spf_txt_records[0]
        if spf_record is None:
            raise SPFRecordNotFound(
                "{0} does not have a SPF TXT record{1}".format(
                    domain, warnings_str))
    except dns.resolver.NoAnswer:
        raise SPFRecordNotFound(
            "{0} does not have a SPF TXT record{1}".format(
                domain, warnings_str))
    except dns.resolver.NXDOMAIN:
        raise SPFRecordNotFound("The domain {0} does not exist".format(domain))
    except Exception as error:
        raise SPFRecordNotFound(error)

    return OrderedDict([("record", spf_record), ("warnings", warnings)])


def parse_spf_record(record, domain, parked=False, seen=None, nameservers=None,
                     timeout=2.0):
    """
    Parses a SPF record, including resolving ``a``, ``mx``, and ``include``
    mechanisms

    Args:
        record (str): An SPF record
        domain (str): The domain that the SPF record came from
        parked (bool): indicated if a domain has been parked
        seen (list): A list of domains seen in past loops
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``dns_lookups`` - Number of DNS lookups required by the record
         - ``parsed`` - An ``OrderedDict`` of a parsed SPF record values
         - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.SPFIncludeLoop`
        :exc:`checkdmarc.SPFRedirectLoop`
        :exc:`checkdmarc.SPFSyntaxError`
        :exc:`checkdmarc.SPFTooManyDNSLookups`
    """
    logging.debug("Parsing the SPF record on {0}".format(domain))
    lookup_mechanisms = ["a", "mx", "include", "exists", "redirect"]
    if seen is None:
        seen = [domain]
    record = record.replace('" ', '').replace('"', '')
    warnings = []
    spf_syntax_checker = _SPFGrammar()
    if parked:
        correct_record = "v=spf1 -all"
        if record != correct_record:
            warnings.append("The SPF record for parked domains should be: "
                            "{0} not: {1}".format(correct_record, record))
    if len(AFTER_ALL_REGEX.findall(record)) > 0:
        warnings.append("Any text after the all mechanism is ignored")
        record = AFTER_ALL_REGEX.sub("all", record)
    parsed_record = spf_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        pos = parsed_record.pos
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        expecting = " or ".join(expecting)
        raise SPFSyntaxError(
            "{0}: Expected {1} at position {2} in: {3}".format(domain,
                                                               expecting,
                                                               pos,
                                                               record))
    matches = SPF_MECHANISM_REGEX.findall(record.lower())
    parsed = OrderedDict([("pass", []),
                          ("neutral", []),
                          ("softfail", []),
                          ("fail", []),
                          ("include", []),
                          ("redirect", None),
                          ("exp", None),
                          ("all", "neutral")])

    lookup_mechanism_count = 0
    for match in matches:
        mechanism = match[1].lower()
        if mechanism in lookup_mechanisms:
            lookup_mechanism_count += 1
    if lookup_mechanism_count > 10:
        raise SPFTooManyDNSLookups(
            "Parsing the SPF record requires {0}/10 maximum DNS lookups - "
            "https://tools.ietf.org/html/rfc7208#section-4.6.4".format(
                lookup_mechanism_count),
            dns_lookups=lookup_mechanism_count)

    for match in matches:
        result = spf_qualifiers[match[0]]
        mechanism = match[1]
        value = match[2]

        try:
            if mechanism in ["ip4", "ip6"]:
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    raise SPFSyntaxError("{0} is not a valid ipv4/ipv6 "
                                         "value".format(value))

            if mechanism == "a":
                if value == "":
                    value = domain
                a_records = _get_a_records(value, nameservers=nameservers,
                                           timeout=timeout)
                if len(a_records) == 0:
                    raise _SPFMissingRecords(
                        "{0} does not have any A/AAAA records".format(
                            value.lower()))
                for record in a_records:
                    parsed[result].append(OrderedDict(
                        [("value", record), ("mechanism", mechanism)]))
            elif mechanism == "mx":
                if value == "":
                    value = domain
                mx_hosts = _get_mx_hosts(value, nameservers=nameservers,
                                         timeout=timeout)
                if len(mx_hosts) == 0:
                    raise _SPFMissingRecords(
                        "{0} does not have any MX records".format(
                            value.lower()))
                if len(mx_hosts) > 10:
                    url = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                    raise SPFTooManyDNSLookups(
                        "{0} has more than 10 MX records - "
                        "{1}".format(value, url), dns_lookups=len(mx_hosts))
                for host in mx_hosts:
                    parsed[result].append(OrderedDict(
                        [("value", host["hostname"]),
                         ("mechanism", mechanism)]))
            elif mechanism == "redirect":
                if value.lower() == domain.lower():
                    raise SPFRedirectLoop(
                        "Redirect loop: {0}".format(value.lower()))
                seen.append(value.lower())
                try:
                    redirect_record = query_spf_record(value,
                                                       nameservers=nameservers,
                                                       timeout=timeout)
                    redirect_record = redirect_record["record"]
                    redirect = parse_spf_record(redirect_record, value,
                                                seen=seen,
                                                nameservers=nameservers,
                                                timeout=timeout)
                    lookup_mechanism_count += redirect["dns_lookups"]
                    if lookup_mechanism_count > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires {0}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4".format(
                                lookup_mechanism_count),
                            dns_lookups=lookup_mechanism_count)
                    parsed["redirect"] = OrderedDict(
                        [("domain", value), ("record", redirect_record),
                         ("dns_lookups", redirect["dns_lookups"]),
                         ("parsed", redirect["parsed"]),
                         ("warnings", redirect["warnings"])])
                    warnings += redirect["warnings"]
                except DNSException as error:
                    raise _SPFWarning(str(error))
            elif mechanism == "exp":
                parsed["exp"] = _get_txt_records(value)[0]
            elif mechanism == "all":
                parsed["all"] = result
            elif mechanism == "include":
                if value.lower() == domain.lower():
                    raise SPFIncludeLoop("Include loop: {0}".format(value))
                if value.lower() in seen:
                    raise _SPFDuplicateInclude(
                        "Duplicate include: {0}".format(value.lower()))
                seen.append(value.lower())
                try:
                    include_record = query_spf_record(value,
                                                      nameservers=nameservers,
                                                      timeout=timeout)
                    include_record = include_record["record"]
                    include = parse_spf_record(include_record, value,
                                               seen=seen,
                                               nameservers=nameservers,
                                               timeout=timeout)
                    lookup_mechanism_count += include["dns_lookups"]
                    if lookup_mechanism_count > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires {0}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4".format(
                                lookup_mechanism_count),
                            dns_lookups=lookup_mechanism_count)
                    include = OrderedDict(
                        [("domain", value), ("record", include_record),
                         ("dns_lookups", include["dns_lookups"]),
                         ("parsed", include["parsed"]),
                         ("warnings", include["warnings"])])
                    parsed["include"].append(include)
                    warnings += include["warnings"]

                except DNSException as error:
                    raise _SPFWarning(str(error))
            elif mechanism == "ptr":
                parsed[result].append(
                    OrderedDict([("value", value), ("mechanism", mechanism)]))
                raise _SPFWarning("The ptr mechanism should not be used - "
                                  "https://tools.ietf.org/html/rfc7208"
                                  "#section-5.5")
            else:
                parsed[result].append(
                    OrderedDict([("value", value), ("mechanism", mechanism)]))

        except (_SPFWarning, DNSException) as warning:
            warnings.append(str(warning))
    return OrderedDict(
        [('dns_lookups', lookup_mechanism_count), ("parsed", parsed),
         ("warnings", warnings)])


def get_spf_record(domain, nameservers=None, timeout=2.0):
    """
    Retrieves and parses an SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout (float): Number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An SPF record parsed by result

    Raises:
        :exc:`checkdmarc.SPFRecordNotFound`
        :exc:`checkdmarc.SPFIncludeLoop`
        :exc:`checkdmarc.SPFRedirectLoop`
        :exc:`checkdmarc.SPFSyntaxError`
        :exc:`checkdmarc.SPFTooManyDNSLookups`

    """
    record = query_spf_record(domain, nameservers=nameservers, timeout=timeout)
    record = record["record"]
    parsed_record = parse_spf_record(record, domain, nameservers=nameservers,
                                     timeout=timeout)
    parsed_record["record"] = record

    return parsed_record


@timeout_decorator.timeout(5, timeout_exception=SMTPError,
                           exception_message="Connection timed out")
def test_tls(hostname, ssl_context=None, cache=None):
    """
    Attempt to connect to a SMTP server port 465 and validate TLS/SSL support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context: A SSL context

    Returns:
        bool: TLS supported
    """
    tls = False
    if cache:
        cached_result = cache.get(hostname, None)
        if cached_result is not None:
            if cached_result["error"] is not None:
                raise SMTPError(cached_result["error"])
            return cached_result["tls"]
    if ssl_context is None:
        ssl_context = create_default_context()
    logging.debug("Testing TLS/SSL on {0}".format(hostname))
    try:
        server = smtplib.SMTP_SSL(hostname, context=ssl_context)
        server.ehlo_or_helo_if_needed()
        tls = True
        try:
            server.quit()
            server.close()
        except Exception as e:
            logging.debug(e)
        finally:
            return tls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except SSLError as e:
        error = "SSL error: {0}".format(e.__str__())
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except CertificateError as e:
        error = "Certificate error: {0}".format(e.__str__())
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = " SMTP error code 554 - Not allowed"
        else:
            message = " SMTP error code {0}".format(error_code)
        error = "Could not connect: {0}".format(message)
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = "HELO error: {0}".format(e.__str__())
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        error_code = error.lstrip("(").split(",")[0]
        error = "SMTP error code {0}".format(error_code)
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except Exception as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    finally:
        if cache:
            cache[hostname] = dict(tls=tls, error=None)
        return tls


@timeout_decorator.timeout(5, timeout_exception=SMTPError,
                           exception_message="Connection timed out")
def test_starttls(hostname, ssl_context=None, cache=None):
    """
    Attempt to connect to a SMTP server and validate STARTTLS support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context: A SSL context

    Returns:
        bool: STARTTLS supported
    """
    starttls = False
    if cache:
        cached_result = cache.get(hostname, None)
        if cached_result is not None:
            if cached_result["error"] is not None:
                raise SMTPError(cached_result["error"])
            return cached_result["starttls"]
    if ssl_context is None:
        ssl_context = create_default_context()
    logging.debug("Testing STARTTLS on {0}".format(hostname))
    try:
        server = smtplib.SMTP(hostname)
        server.ehlo_or_helo_if_needed()
        if server.has_extn("starttls"):
            server.starttls(context=ssl_context)
            server.ehlo()
            starttls = True
        try:
            server.quit()
            server.close()
        except Exception as e:
            logging.debug(e)
        finally:
            if cache:
                cache[hostname] = dict(starttls=starttls, error=None)
            return starttls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except SSLError as e:
        error = "SSL error: {0}".format(e.__str__())
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except CertificateError as e:
        error = "Certificate error: {0}".format(e.__str__())
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = " SMTP error code 554 - Not allowed"
        else:
            message = " SMTP error code {0}".format(error_code)
        error = "Could not connect: {0}".format(message)
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = "HELO error: {0}".format(e.__str__())
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        error_code = error.lstrip("(").split(",")[0]
        error = "SMTP error code {0}".format(error_code)
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except Exception as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)


def get_mx_hosts(domain, skip_tls=False,
                 approved_hostnames=None, parked=False,
                 nameservers=None, timeout=2.0):
    """
    Gets MX hostname and their addresses

    Args:
        domain (str): A domain name
        skip_tls (bool): Skip STARTTLS testing
        approved_hostnames (list): A list of approved MX hostname substrings
        parked (bool): Indicates that the domains are parked
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``hosts`` - A ``list`` of ``OrderedDict`` with keys of

                       - ``hostname`` - A hostname
                       - ``addresses`` - A ``list`` of IP addresses

                     - ``warnings`` - A ``list`` of MX resolution warnings

    """
    hosts = []
    warnings = []
    hostnames = set()
    dupe_hostnames = set()
    mx_records = _get_mx_hosts(domain, nameservers=nameservers,
                               timeout=timeout)
    for record in mx_records:
        hosts.append(OrderedDict([("preference", record["preference"]),
                                  ("hostname", record["hostname"].lower()),
                                  ("addresses", [])]))
    if parked and len(hosts) > 0:
        warnings.append("MX records found on parked domains")
    elif not parked and len(hosts) == 0:
        warnings.append("No MX records found. Is the domain parked?")

    if approved_hostnames:
        approved_hostnames = list(map(lambda h: h.lower(),
                                      approved_hostnames))
    for host in hosts:
        if host["hostname"] in hostnames:
            if host["hostname"] not in dupe_hostnames:
                warnings.append(
                    "Hostname {0} is listed in multiple MX records".format(
                        host["hostname"]))
                dupe_hostnames.add(host["hostname"])
            continue
        hostnames.add(host["hostname"])
        if approved_hostnames:
            approved = False
            for approved_hostname in approved_hostnames:
                if approved_hostname in host["hostname"]:
                    approved = True
                    break
            if not approved:
                warnings.append("Unapproved MX hostname: {0}".format(
                    host["hostname"]
                ))

        try:
            host["addresses"] = []
            host["addresses"] = _get_a_records(host["hostname"],
                                               nameservers=nameservers,
                                               timeout=timeout)
            if len(host["addresses"]) == 0:
                warnings.append(
                    "{0} does not have any A or AAAA DNS records".format(
                        host["hostname"]
                    ))
        except Exception as e:
            if host["hostname"].lower().endswith(".msv1.invalid"):
                warnings.append("{0}. Consider using a TXT record to validate "
                                "domain ownership in Office 365 instead."
                                "".format(e.__str__()))
            else:
                warnings.append(e.__str__())

        for address in host["addresses"]:
            reverse_hostnames = _get_reverse_dns(address,
                                                 nameservers=nameservers,
                                                 timeout=timeout)
            if len(reverse_hostnames) == 0:
                warnings.append(
                    "{0} does not have any reverse DNS (PTR) "
                    "records".format(address))
            for hostname in reverse_hostnames:
                try:
                    _addresses = _get_a_records(hostname)
                except DNSException as warning:
                    warnings.append(str(warning))
                    _addresses = []
                if address not in _addresses:
                    warnings.append("The reverse DNS of {1} is {0}, but "
                                    "the A/AAAA DNS records for "
                                    "{0} do not resolve to "
                                    "{1}".format(hostname, address))
        if not skip_tls and platform.system() == "Windows":
            logging.warning("Testing TLS is not supported on Windows")
            skip_tls = True
        if skip_tls:
            logging.debug("Skipping TLS/SSL tests on {0}".format(
                host["hostname"]))
        else:
            try:
                starttls = test_starttls(host["hostname"],
                                         cache=STARTTLS_CACHE)
                if not starttls:
                    warnings.append("STARTTLS is not supported on {0}".format(
                        host["hostname"]))
                tls = test_tls(host["hostname"], cache=TLS_CACHE)

                if not tls:
                    warnings.append("SSL/TLS is not supported on {0}".format(
                        host["hostname"]))
                host["tls"] = tls
                host["starttls"] = starttls
            except DNSException as warning:
                warnings.append(str(warning))
                tls = False
                starttls = False
                host["tls"] = tls
                host["starttls"] = starttls
            except SMTPError as error:
                tls = False
                starttls = False
                warnings.append("{0}: {1}".format(host["hostname"], error))

                host["tls"] = tls
                host["starttls"] = starttls

    return OrderedDict([("hosts", hosts), ("warnings", warnings)])


def get_nameservers(domain, approved_nameservers=None,
                    nameservers=None, timeout=2.0):
    """
    Gets a list of nameservers for a given domain

    Args:
        domain (str): A domain name
        approved_nameservers (list): A list of approved nameserver substrings
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an record from DNS

    Returns:
        Dict: A dictionary with the following keys:
              - ``hostnames`` - A list of nameserver hostnames
              - ``warnings``  - A list of warnings
    """
    logging.debug("Getting NS records on {0}".format(domain))
    warnings = []

    ns_records = _get_nameservers(domain, nameservers=nameservers,
                                  timeout=timeout)

    if approved_nameservers:
        approved_nameservers = list(map(lambda h: h.lower(),
                                        approved_nameservers))
    for nameserver in ns_records:
        if approved_nameservers:
            approved = False
            for approved_nameserver in approved_nameservers:
                if approved_nameserver in nameserver.lower():
                    approved = True
                    break
            if not approved:
                warnings.append("Unapproved nameserver: {0}".format(
                    nameserver
                ))

    return OrderedDict([("hostnames", ns_records), ("warnings", warnings)])


def test_dnssec(domain, nameservers=None, timeout=2.0):
    """
    Check for DNSSEC on the given domain

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds

    Returns:
        bool: DNSSEC status
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers

    request = dns.message.make_query(get_base_domain(domain),
                                     dns.rdatatype.NS,
                                     want_dnssec=True)
    for nameserver in nameservers:
        try:
            response = dns.query.udp(request, nameserver, timeout=timeout)
            if response is not None:
                for record in response.answer:
                    if record.rdtype == dns.rdatatype.RRSIG:
                        if response.flags & dns.flags.AD:
                            return True
        except Exception as e:
            logging.debug("DNSSEC query error: {0}".format(e))

    return False


def check_domains(domains, parked=False,
                  approved_nameservers=None,
                  approved_mx_hostnames=None,
                  skip_tls=False,
                  include_dmarc_tag_descriptions=False,
                  nameservers=None, timeout=2.0, wait=0.0):
    """
    Check the given domains for SPF and DMARC records, parse them, and return
    them

    Args:
        domains (list): A list of domains to check
        parked (bool): Indicates that the domains are parked
        approved_nameservers (list): A list of approved nameservers
        approved_mx_hostnames (list): A list of approved MX hostname
        skip_tls (bool: Skip STARTTLS testing
        include_dmarc_tag_descriptions (bool): Include descriptions of DMARC
                                               tags and/or tag values in the
                                               results
        nameservers (list): A list of nameservers to query
        timeout (float): number of seconds to wait for an answer from DNS
        wait (float): number of seconds to wait between processing domains

    Returns:
       An ``OrderedDict`` or ``list`` of  `OrderedDict` with the following keys

       - ``domain`` - The domain name
       - ``base_domain`` The base domain
       - ``mx`` - See :func:`checkdmarc.get_mx_hosts`
       - ``spf`` -  A ``valid`` flag, plus the output of
         :func:`checkdmarc.parse_spf_record` or an ``error``
       - ``dmarc`` - A ``valid`` flag, plus the output of
         :func:`checkdmarc.parse_dmarc_record` or an ``error``
    """
    domains = sorted(list(set(
        map(lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0],
            domains))))
    not_domains = []
    for domain in domains:
        if "." not in domain:
            not_domains.append(domain)
    for domain in not_domains:
        domains.remove(domain)
    while "" in domains:
        domains.remove("")
    results = []
    for domain in domains:
        domain = domain.lower()
        logging.debug("Checking: {0}".format(domain))
        domain_results = OrderedDict(
            [("domain", domain), ("base_domain", get_base_domain(domain)),
             ("dnssec", None), ("ns", []), ("mx", [])])
        domain_results["spf"] = OrderedDict(
            [("record", None), ("valid", True), ("dns_lookups", None)])
        domain_results["dnssec"] = test_dnssec(domain,
                                               nameservers=nameservers,
                                               timeout=timeout)
        try:
            domain_results["ns"] = get_nameservers(
                domain,
                approved_nameservers=approved_nameservers,
                nameservers=nameservers,
                timeout=timeout)
        except DNSException as error:
            domain_results["ns"] = OrderedDict([("hostnames", []),
                                                ("error", error.__str__())])
        try:
            domain_results["mx"] = get_mx_hosts(
                domain,
                skip_tls=skip_tls,
                approved_hostnames=approved_mx_hostnames,
                nameservers=nameservers,
                timeout=timeout)
        except DNSException as error:
            domain_results["mx"] = OrderedDict([("hosts", []),
                                                ("error", error.__str__())])
        try:
            spf_query = query_spf_record(
                domain,
                nameservers=nameservers,
                timeout=timeout)
            domain_results["spf"]["record"] = spf_query["record"]
            domain_results["spf"]["warnings"] = spf_query["warnings"]
            parsed_spf = parse_spf_record(domain_results["spf"]["record"],
                                          domain_results["domain"],
                                          parked=parked,
                                          nameservers=nameservers,
                                          timeout=timeout)

            domain_results["spf"]["dns_lookups"] = parsed_spf[
                "dns_lookups"]
            domain_results["spf"]["parsed"] = parsed_spf["parsed"]
            domain_results["spf"]["warnings"] += parsed_spf["warnings"]
        except SPFError as error:
            domain_results["spf"]["error"] = str(error)
            del domain_results["spf"]["dns_lookups"]
            domain_results["spf"]["valid"] = False
            if hasattr(error, "data") and error.data:
                for key in error.data:
                    domain_results["spf"][key] = error.data[key]

        # DMARC
        domain_results["dmarc"] = OrderedDict([("record", None),
                                               ("valid", True),
                                               ("location", None)])
        try:
            dmarc_query = query_dmarc_record(domain,
                                             nameservers=nameservers,
                                             timeout=timeout)
            domain_results["dmarc"]["record"] = dmarc_query["record"]
            domain_results["dmarc"]["location"] = dmarc_query["location"]
            parsed_dmarc_record = parse_dmarc_record(
                dmarc_query["record"],
                dmarc_query["location"],
                parked=parked,
                include_tag_descriptions=include_dmarc_tag_descriptions,
                nameservers=nameservers,
                timeout=timeout)
            domain_results["dmarc"]["warnings"] = dmarc_query["warnings"]

            domain_results["dmarc"]["tags"] = parsed_dmarc_record["tags"]
            domain_results["dmarc"]["warnings"] += parsed_dmarc_record[
                "warnings"]
        except DMARCError as error:
            domain_results["dmarc"]["error"] = str(error)
            domain_results["dmarc"]["valid"] = False
            if hasattr(error, "data") and error.data:
                for key in error.data:
                    domain_results["dmarc"][key] = error.data[key]
        results.append(domain_results)
        if wait > 0.0:
            logging.debug("Sleeping for {0} seconds".format(wait))
            sleep(wait)
    if len(results) == 1:
        results = results[0]

    return results


def results_to_json(results):
    """
    Converts a dictionary of results to a JSON string

    Args:
        results (dict): A dictionary of results

    Returns:
        str: Results in JSON format
    """
    return json.dumps(results, ensure_ascii=False, indent=2)


def results_to_csv_rows(results):
    """
    Converts a dictionary of results list of CSV row dicts

    Args:
        results (dict): A dictionary of results

    Returns:
        list: A list of CSV row dicts
    """
    rows = []

    if type(results) == OrderedDict:
        results = [results]

    for result in results:
        row = dict()
        ns = result["ns"]
        mx = result["mx"]
        spf = result["spf"]
        dmarc = result["dmarc"]
        row["domain"] = result["domain"]
        row["base_domain"] = result["base_domain"]
        row["dnssec"] = result["dnssec"]
        row["ns"] = "|".join(ns["hostnames"])
        if "error" in ns:
            row["ns_error"] = ns["error"]
        else:
            row["ns_warnings"] = "|".join(ns["warnings"])
        row["mx"] = "|".join(list(
            map(lambda r: "{0} {1}".format(r["preference"], r["hostname"]),
                mx["hosts"])))
        tls = None
        try:
            tls_results = list(
                map(lambda r: "{0}".format(r["starttls"]),
                    mx["hosts"]))
            for tls_result in tls_results:
                tls = tls_result
                if tls_result is False:
                    tls = False
                    break
        except KeyError:
            # The user might opt to skip the STARTTLS test
            pass
        finally:
            row["tls"] = tls

        starttls = None
        try:
            starttls_results = list(
                map(lambda r: "{0}".format(r["starttls"]),
                    mx["hosts"]))
            for starttls_result in starttls_results:
                starttls = starttls_result
                if starttls_result is False:
                    starttls = False
        except KeyError:
            # The user might opt to skip the STARTTLS test
            pass
        finally:
            row["starttls"] = starttls

        if "error" in mx:
            row["mx_error"] = mx["error"]
        else:
            row["mx_warnings"] = "|".join(mx["warnings"])
        row["spf_record"] = spf["record"]
        row["spf_valid"] = spf["valid"]
        if "error" in spf:
            row["spf_error"] = spf["error"]
        else:
            row["spf_warnings"] = "|".join(spf["warnings"])

        row["dmarc_record"] = dmarc["record"]
        row["dmarc_record_location"] = dmarc["location"]
        row["dmarc_valid"] = dmarc["valid"]
        if "error" in dmarc:
            row["dmarc_error"] = dmarc["error"]
        else:
            row["dmarc_adkim"] = dmarc["tags"]["adkim"]["value"]
            row["dmarc_aspf"] = dmarc["tags"]["aspf"]["value"]
            row["dmarc_fo"] = ":".join(dmarc["tags"]["fo"]["value"])
            row["dmarc_p"] = dmarc["tags"]["p"]["value"]
            row["dmarc_pct"] = dmarc["tags"]["pct"]["value"]
            row["dmarc_rf"] = ":".join(dmarc["tags"]["rf"]["value"])
            row["dmarc_ri"] = dmarc["tags"]["ri"]["value"]
            row["dmarc_sp"] = dmarc["tags"]["sp"]["value"]
            if "rua" in dmarc["tags"]:
                addresses = dmarc["tags"]["rua"]["value"]
                addresses = list(map(lambda u: u["scheme"] + ":" +
                                               u["address"], addresses))
                row["dmarc_rua"] = "|".join(addresses)
            if "ruf" in dmarc["tags"]:
                addresses = dmarc["tags"]["ruf"]["value"]
                addresses = list(map(lambda u: u["address"], addresses))
                row["dmarc_ruf"] = "|".join(addresses)
            row["dmarc_warnings"] = "|".join(dmarc["warnings"])
        rows.append(row)
    return rows


def results_to_csv(results):
    """
    Converts a dictionary of results to CSV

    Args:
        results (dict): A dictionary of results

    Returns:
        str: A CSV of results
    """
    fields = ["domain", "base_domain", "dnssec", "spf_valid", "dmarc_valid",
              "dmarc_adkim", "dmarc_aspf",
              "dmarc_fo", "dmarc_p", "dmarc_pct", "dmarc_rf", "dmarc_ri",
              "dmarc_rua", "dmarc_ruf", "dmarc_sp",
              "mx", "tls", "starttls", "spf_record", "dmarc_record",
              "dmarc_record_location", "mx_error",
              "mx_warnings", "spf_error",
              "spf_warnings", "dmarc_error", "dmarc_warnings",
              "ns", "ns_error", "ns_warnings"]
    output = StringIO(newline="\n")
    writer = DictWriter(output, fieldnames=fields)
    writer.writeheader()
    rows = results_to_csv_rows(results)
    writer.writerows(rows)
    output.flush()

    return output.getvalue()


def output_to_file(path, content):
    """
    Write given content to the given path

    Args:
        path (str): A file path
        content (str): JSON or CSV text
    """
    with open(path, "w", newline="\n", encoding="utf-8",
              errors="ignore") as output_file:
        output_file.write(content)


def _main():
    """Called when the module in executed"""
    arg_parser = ArgumentParser(description=__doc__)
    arg_parser.add_argument("domain", nargs="+",
                            help="one or more domains, or a single path to a "
                                 "file containing a list of domains")
    arg_parser.add_argument("-p", "--parked", help="indicate that the "
                                                   "domains are parked",
                            action="store_true", default=False)
    arg_parser.add_argument("--ns", nargs="+",
                            help="approved nameserver substrings")
    arg_parser.add_argument("--mx", nargs="+",
                            help="approved MX hostname substrings")
    arg_parser.add_argument("-d", "--descriptions", action="store_true",
                            help="include descriptions of DMARC tags in "
                                 "the JSON output")
    arg_parser.add_argument("-f", "--format", default="json",
                            help="specify JSON or CSV screen output format")
    arg_parser.add_argument("-o", "--output", nargs="+",
                            help="one or more file paths to output to "
                                 "(must end in .json or .csv) "
                                 "(silences screen output)")
    arg_parser.add_argument("-n", "--nameserver", nargs="+",
                            help="nameservers to query")
    arg_parser.add_argument("-t", "--timeout",
                            help="number of seconds to wait for an answer "
                                 "from DNS (default 2.0)",
                            type=float,
                            default=2.0)
    arg_parser.add_argument("-v", "--version", action="version",
                            version=__version__)
    arg_parser.add_argument("-w", "--wait", type=float,
                            help="number of seconds to wait between "
                                 "checking domains (default 0.0)",
                            default=0.0),
    arg_parser.add_argument("--skip-tls", action="store_true",
                            help="skip TLS/SSL testing")
    arg_parser.add_argument("--debug", action="store_true",
                            help="enable debugging output")

    args = arg_parser.parse_args()

    logging_format = "%(asctime)s - %(levelname)s: %(message)s"
    logging.basicConfig(level=logging.WARNING, format=logging_format)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug output enabled")
    domains = args.domain
    if len(domains) == 1 and os.path.exists(domains[0]):
        with open(domains[0]) as domains_file:
            domains = sorted(list(set(
                map(lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0],
                    domains_file.readlines()))))
            not_domains = []
            for domain in domains:
                if "." not in domain:
                    not_domains.append(domain)
            for domain in not_domains:
                domains.remove(domain)

    results = check_domains(domains, skip_tls=args.skip_tls,
                            parked=args.parked,
                            approved_nameservers=args.ns,
                            approved_mx_hostnames=args.mx,
                            include_dmarc_tag_descriptions=args.descriptions,
                            nameservers=args.nameserver, timeout=args.timeout,
                            wait=args.wait)

    if args.output is None:
        if args.format.lower() == "json":
            results = results_to_json(results)
        elif args.format.lower() == "csv":
            results = results_to_csv(results)
        print(results)
    else:
        for path in args.output:
            json_path = path.lower().endswith(".json")
            csv_path = path.lower().endswith(".csv")

            if not json_path and not csv_path:
                logging.error(
                    "Output path {0} must end in .json or .csv".format(path))
            else:
                if path.lower().endswith(".json"):
                    output_to_file(path, results_to_json(results))
                elif path.lower().endswith(".csv"):
                    output_to_file(path, results_to_csv(results))


if __name__ == "__main__":
    _main()