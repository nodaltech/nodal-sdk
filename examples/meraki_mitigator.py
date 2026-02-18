import os
import yaml
import asyncio
import time
from typing import Optional
import traceback
from nodal_sdk import Mitigator
from nodal_sdk.mitigator import Mitigation

import meraki
from meraki.exceptions import APIError

# Rule configuration
RULE_NAME_PREFIX = "NODAL_MIT"
RULE_POLICY = "deny"
RULE_PROTOCOL = "any"
RULE_SRC_PORT = "any"
RULE_DST_PORT = "any"

network_id_global = None


def get_meraki_dashboard(conf) -> meraki.DashboardAPI:
    """Get authenticated Meraki Dashboard API instance"""
    if conf.get("MERAKI_API_KEY") is None or len(conf.get("MERAKI_API_KEY", "")) < 5:
        raise ValueError("MERAKI_API_KEY is not configured")

    try:
        dashboard = meraki.DashboardAPI(
            api_key=conf["MERAKI_API_KEY"], suppress_logging=True
        )
        return dashboard
    except Exception as e:
        raise


def discover_organization_id(dashboard: meraki.DashboardAPI, conf) -> Optional[str]:
    """Discover organization ID from API"""
    try:
        organizations = dashboard.organizations.getOrganizations()
        if not organizations:
            return None

        # If only one org, return it
        if len(organizations) == 1:
            org_id = organizations[0]["id"]
            return org_id

        # If MERAKI_ORG_ID is set, try to use it
        if conf.get("MERAKI_ORG_ID") != None and len(conf.get("MERAKI_ORG_ID", "")) > 0:
            for org in organizations:
                if org["id"] == conf["MERAKI_ORG_ID"]:
                    return conf["MERAKI_ORG_ID"]

        org_id = organizations[0]["id"]
        return org_id

    except APIError as e:
        return None


def discover_network_id(
    dashboard: meraki.DashboardAPI, org_id: str, conf
) -> Optional[str]:
    """Discover network ID from API"""
    try:
        networks = dashboard.organizations.getOrganizationNetworks(org_id)
        if not networks:
            return None

        # If MERAKI_NETWORK_ID is set, try to use it
        if conf.get("MERAKI_NETWORK_ID") != None and len(conf["MERAKI_NETWORK_ID"]) > 0:
            for net in networks:
                if net["id"] == conf["MERAKI_NETWORK_ID"]:
                    return conf["MERAKI_NETWORK_ID"]

        # If MERAKI_NETWORK_NAME is set, search by name
        if (
            conf.get("MERAKI_NETWORK_NAME") != None
            and len(conf["MERAKI_NETWORK_NAME"]) > 0
        ):
            for net in networks:
                if net["name"] == conf["MERAKI_NETWORK_NAME"]:
                    return net["id"]

        network_id = networks[0]["id"]
        return network_id

    except APIError as e:
        return None


def generate_rule_comment(ext_ip, int_ip) -> str:
    """Generate a unique comment for the mitigation rule"""
    timestamp = int(time.time())
    return f"{RULE_NAME_PREFIX} {ext_ip} {int_ip} {timestamp}"


async def main():
    global network_id_global

    cf = "meraki_mitigator.yaml"
    conf = None
    if os.path.isfile(cf):
        print("loading config from " + cf, flush=True)
        with open(cf, "r") as f:
            conf = yaml.safe_load(f)

        # Test connection and discover IDs
        try:
            dashboard = get_meraki_dashboard(conf)
            org_id = discover_organization_id(dashboard, conf)

            if not org_id:
                raise RuntimeError(
                    "Meraki org_id could not be discovered (check API key access)"
                )

            network_id_global = discover_network_id(dashboard, org_id, conf)
            if not network_id_global:
                raise RuntimeError(
                    "Meraki network_id could not be discovered (check MERAKI_NETWORK_ID/NAME)"
                )

        except Exception as e:
            print(f"error using Meraki API to find network_id: {e}")
            exit(2)

    else:
        with open(cf, "w") as fout:
            fout.write('COMPONENT_NAME: "" # Component name configured in your ghost\n')
            fout.write(
                'COMPONENT_TOKEN: "" # Component token configured in your ghost\n'
            )
            fout.write(
                'COMPONENT_IP: "127.0.0.1" # Addr where brain can reach this component\n'
            )
            fout.write(
                "LISTEN_PORT: 2000  # Port for brain to connect to this component on\n"
            )
            fout.write(
                'GHOST_URL: "http://localhost:8080/api/components/handshake" # usually https://<ghost fqdn>/api/components/handshake\n'
            )
            fout.write('MERAKI_API_KEY: ""  # Your Meraki API key\n')
            fout.write(
                'MERAKI_ORG_ID: ""  # Optional, if not specified it will be looked up\n'
            )
            fout.write(
                'MERAKI_NETWORK_ID: ""  # Optional, if not specified it will be looked up\n'
            )
            fout.write(
                'MERAKI_NETWORK_NAME: ""  # Optional, can be used to lookup network id\n'
            )
        print("wrote config file " + cf + " in local dir, please edit it")
        exit(1)

    mitigator = Mitigator(conf["COMPONENT_NAME"], conf["LISTEN_PORT"])
    await mitigator.register(
        conf["COMPONENT_IP"], conf["GHOST_URL"], conf["COMPONENT_TOKEN"]
    )

    async def enable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        if "IntExtIp" in data["targets"] or "GlobalIp" in data["targets"]:
            tag = data["tag"]
            target = None
            ext_ip = None
            int_ip = None
            if "IntExtIp" in data["targets"]:
                target = data["targets"]["IntExtIp"]
                ext_ip = target["ext_ip"]
                int_ip = target["int_ip"]
            elif "GlobalIp" in data["targets"]:
                target = data["targets"]["GlobalIp"]
                ext_ip = target["ext_ip"]
                int_ip = "any"

            print(f"Adding Meraki rules for {tag} {int_ip} <-> {ext_ip}")

            try:
                dashboard = get_meraki_dashboard(conf)

                # Get current firewall rules
                current_rules_response = (
                    dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(
                        network_id_global
                    )
                )
                current_rules = current_rules_response.get("rules", [])

                # Generate unique comment for tracking
                rule_comment = generate_rule_comment(ext_ip, int_ip)

                src_cidr = int_ip
                if int_ip != "any":
                    src_cidr += "/32"

                # Create the new deny rule
                new_rule = {
                    "policy": RULE_POLICY,
                    "protocol": RULE_PROTOCOL,
                    "srcCidr": src_cidr,
                    "srcPort": RULE_SRC_PORT,
                    "destCidr": ext_ip + "/32",  # Block specific destination IP
                    "destPort": RULE_DST_PORT,
                    "comment": rule_comment,
                }

                # Deduplicate rules
                def rule_key(r):
                    return (
                        str(r.get("policy", "")).lower(),
                        str(r.get("protocol", "")).lower(),
                        str(r.get("srcCidr", "")).lower(),
                        str(r.get("destCidr", r.get("dstCidr", ""))).lower(),
                        str(r.get("srcPort", "")).lower(),
                        str(r.get("destPort", "")).lower(),
                    )

                seen = set()
                deduplicated_rules = []
                for rule in current_rules:
                    # Skip default rules
                    comment = str(rule.get("comment", "")).lower()
                    if "default" in comment:
                        continue
                    key = rule_key(rule)
                    if key not in seen:
                        seen.add(key)
                        deduplicated_rules.append(rule)

                new_key = rule_key(new_rule)
                if new_key in seen:
                    return

                updated_rules = [new_rule] + deduplicated_rules

                dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
                    network_id_global, rules=updated_rules
                )

                mitigation.set_enabled()
                print(f"Successfully added Meraki rules to block {ext_ip} <-> {int_ip}")
                return mitigation

            except Exception as e:
                print(f"Error adding Meraki rules: {e}")

    async def disable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        if "IntExtIp" in data["targets"] or "GlobalIp" in data["targets"]:
            tag = data["tag"]
            target = None
            ext_ip = None
            int_ip = None
            if "IntExtIp" in data["targets"]:
                target = data["targets"]["IntExtIp"]
                ext_ip = target["ext_ip"]
                int_ip = target["int_ip"]
            elif "GlobalIp" in data["targets"]:
                target = data["targets"]["GlobalIp"]
                ext_ip = target["ext_ip"]
                int_ip = "any"

            print(f"Removing Meraki rules for {int_ip} <-> {ext_ip}")
            try:
                dashboard = get_meraki_dashboard(conf)

                # Get current firewall rules from API
                current_rules_response = (
                    dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(
                        network_id_global
                    )
                )
                current_rules = current_rules_response.get("rules", [])

                # Build expected CIDRs
                expected_src_cidr = int_ip
                if int_ip != "any":
                    expected_src_cidr += "/32"
                expected_dest_cidr = f"{ext_ip}/32"

                # Find and remove rules matching our prefix and the correct src/dest CIDRs
                updated_rules = []
                for rule in current_rules:
                    comment = rule.get("comment", "")
                    src_cidr = rule.get("srcCidr", "")
                    dest_cidr = rule.get("destCidr", "") or rule.get("dstCidr", "")

                    # Skip default rules
                    if "default" in comment.lower():
                        continue

                    # Keep rule unless it matches our pattern and CIDRs
                    if (
                        RULE_NAME_PREFIX in comment
                        and src_cidr == expected_src_cidr
                        and dest_cidr == expected_dest_cidr
                    ):
                        continue

                    updated_rules.append(rule)

                if len(updated_rules) != len(current_rules):
                    dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
                        network_id_global, rules=updated_rules
                    )

                mitigation.set_disabled()
                print(f"Successfully removed Meraki rules for {int_ip} <-> {ext_ip}")
                return mitigation
            except Exception as e:
                print(f"Error removing Meraki rules: {e}")

    async def refresh(_: Mitigation) -> Mitigation | None:
        # this gets called when the brain extends expiry on an existing mitigation
        # nothing to do here unless you want to double check the existing rule
        # SDK automatically extends the expiry
        pass

    while True:
        try:
            await mitigator.handle(enable, disable, refresh)
        except Exception as e:
            traceback.print_exception(e)


if __name__ == "__main__":
    asyncio.run(main())
