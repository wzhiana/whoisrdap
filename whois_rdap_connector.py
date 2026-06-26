# File: whois_rdap_connector.py
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
#
#
import ipaddress
import json
import os
import sys
import traceback

import ssl
import urllib.request

import dns.resolver

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from whois_rdap_consts import *


class WhoisRDAPConnector(BaseConnector):
    # actions supported by this script
    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"

    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

    def _is_valid_ip(self, input_ip_address):
        """Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        try:
            ipaddress.ip_address(input_ip_address)
        except Exception:
            return False

        return True

    def initialize(self):
        # use this to store data that needs to be accessed across actions
        self._state = self.load_state()
        self.set_validator("ipv6", self._is_valid_ip)
        return phantom.APP_SUCCESS

    def _whois_ip(self, param):
        ip = param[phantom.APP_JSON_IP]

        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result.set_param({phantom.APP_JSON_IP: ip})

        self.debug_print(f"Validating/Querying IP '{ip}'")

        self.save_progress("Querying...")

        status, whois_response = self._lookup_rdap(action_result, ip)

        if phantom.is_fail(status):
            return action_result.get_status()

        self.save_progress("Parsing response")

        # the format screws with the object model since the keys change with every run
        # but the keys aren't needed since they are also stored in object.[key].handle
        # changing this to a list

        if whois_response.get("objects"):
            objects = whois_response["objects"]
            new_objects = [objects[key] for key in objects]
            whois_response["objects"] = new_objects

        action_result.add_data(whois_response)

        summary = action_result.update_summary({})

        # Create the summary and the message
        if "asn_registry" in whois_response:
            summary.update({WHOIS_JSON_ASN_REGISTRY: whois_response["asn_registry"]})

        if "asn" in whois_response:
            summary.update({WHOIS_JSON_ASN: whois_response["asn"]})

        if "asn_country_code" in whois_response:
            summary.update({WHOIS_JSON_COUNTRY_CODE: whois_response["asn_country_code"]})

        if "network" in whois_response:
            nets = whois_response["network"]
            wanted_keys = ["start_address", "end_address"]
            summary[WHOIS_JSON_NETS] = []
            summary_net = {x: nets[x] for x in wanted_keys}
            summary[WHOIS_JSON_NETS].append(summary_net)

        action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        ip = "8.8.8.8"

        self.debug_print(f"Validating/Querying IP '{ip}'")

        self.save_progress("Querying...")

        status, whois_response = self._lookup_rdap(self, ip)
        if not status:
            return status

        self.save_progress("Parsing response")

        if whois_response.get("query") and whois_response.get("query") == ip:
            self.debug_print("identity test passed")
            return self.set_status_save_progress(phantom.APP_SUCCESS, WHOIS_SUCCESS_CONNECTIVITY_TEST)

        self.debug_print("identity test failed")
        return self.set_status_save_progress(phantom.APP_ERROR, WHOIS_ERROR_CONNECTIVITY_TEST)

    def _lookup_rdap(self, action_result, ip):
        # Check for private/reserved IPs before making network calls
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local \
                    or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                msg = f"IPv{ip_obj.version} address {ip} is already defined as a special-use address."
                action_result.set_status(phantom.APP_SUCCESS, msg)
                return phantom.APP_ERROR, None
        except ValueError:
            pass

        try:
            whois_response = self._rdap_request(ip)
            return phantom.APP_SUCCESS, whois_response
        except Exception as e:
            tb = traceback.format_exc()
            self.error_print(f"Got exception ({type(e).__name__}): {e}\n{tb}")
            return action_result.set_status(phantom.APP_ERROR, WHOIS_ERROR_QUERY.format(e)), None

    def _rdap_request(self, ip):
        """Make RDAP lookup using urllib.request with a custom TLS context.

        Excludes post-quantum key exchange groups (X25519MLKEM768) from the
        ClientHello that trigger TCP RST from SSL-inspection appliances
        on OpenSSL 3.5+.  TLS 1.3 is still supported with classical groups.
        """
        url = f"https://rdap.arin.net/registry/ip/{ip}"

        # Resolve CA bundle (REQUESTS_CA_BUNDLE > CURL_CA_BUNDLE > certifi)
        ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")
        if not ca_bundle or not os.path.isfile(ca_bundle):
            try:
                import certifi
                ca_bundle = certifi.where()
            except ImportError:
                ca_bundle = None

        # Build TLS context with only classical key exchange groups
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ecdh_curve("X25519:P-256:P-384:P-521")
        if ca_bundle and os.path.isfile(ca_bundle):
            ctx.load_verify_locations(ca_bundle)
        else:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)

        handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        resp = opener.open(req, timeout=30)
        final_url = resp.url
        data = json.loads(resp.read().decode("utf-8"))

        # Determine registry from the final URL after any redirects
        final_url = resp.url
        registry = "arin"
        for reg, host in [("ripencc", "ripe.net"), ("apnic", "apnic.net"),
                          ("lacnic", "lacnic.net"), ("afrinic", "afrinic.net")]:
            if host in final_url:
                registry = reg
                break

        asn, asn_cidr, asn_country, asn_desc = self._cymru_asn_lookup(ip)

        objects = {}
        for entity in data.get("entities", []):
            handle = entity.get("handle") or ",".join(entity.get("roles", ["unknown"]))
            obj = {
                "handle": handle,
                "roles": entity.get("roles", []),
                "status": entity.get("status", []),
                "links": entity.get("links", []),
                "events": entity.get("events", []),
                "entities": entity.get("entities", []),
            }
            if "vcardArray" in entity:
                obj["contact"] = self._parse_vcard(entity["vcardArray"])
            objects[handle] = obj

        return {
            "query": ip,
            "asn_registry": registry,
            "asn": asn,
            "asn_cidr": asn_cidr,
            "asn_country_code": asn_country or data.get("country"),
            "asn_date": None,
            "asn_description": asn_desc,
            "network": {
                "handle": data.get("handle"),
                "start_address": data.get("startAddress"),
                "end_address": data.get("endAddress"),
                "name": data.get("name"),
                "type": data.get("type"),
                "parent_handle": data.get("parentHandle"),
                "ip_version": data.get("ipVersion"),
                "country": data.get("country"),
                "status": data.get("status"),
                "events": data.get("events"),
                "links": data.get("links"),
                "remarks": data.get("remarks"),
            },
            "objects": objects,
        }

    def _cymru_asn_lookup(self, ip):
        """Resolve ASN info via Cymru DNS service."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                rev = ".".join(reversed(ip.split(".")))
                qname = f"{rev}.origin.asn.cymru.com"
            else:
                nibbles = ip_obj.exploded.replace(":", "")
                rev = ".".join(reversed(nibbles))
                qname = f"{rev}.origin6.asn.cymru.com"
            answers = dns.resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 4:
                    return (
                        parts[0] or None,
                        parts[1] or None,
                        parts[3] or None,
                        parts[4] if len(parts) > 4 else None,
                    )
        except Exception:
            pass
        return None, None, None, None

    def _parse_vcard(self, vcard_array):
        contact = {}
        try:
            for field in vcard_array[1]:
                name = field[0] if field else ""
                val = field[3] if len(field) > 3 else ""
                if name == "fn":
                    contact["name"] = val
                elif name == "email":
                    contact["email"] = val
                elif name in ("tel",):
                    contact["phone"] = val
                elif name == "adr":
                    contact["address"] = val
                elif name == "org":
                    contact["org"] = val
        except Exception:
            pass
        return contact

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if action == self.ACTION_ID_WHOIS_IP:
            result = self._whois_ip(param)
        elif action == self.ACTION_ID_TEST_CONNECTIVITY:
            self._handle_test_connectivity(param)
        else:
            result = self.unknown_action()

        return result


if __name__ == "__main__":
    import sys

    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=" " * 4))

        connector = WhoisRDAPConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
