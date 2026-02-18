import os
import yaml
import boto3
from botocore.exceptions import ClientError
import asyncio
import traceback
from nodal_sdk import Mitigator
from nodal_sdk.mitigator import Mitigation


def prep_ec2(conf, _):
    # Initialize boto3 client with credentials and region
    ec2 = boto3.client(
        "ec2",
        region_name=conf["AWS_REGION"],
        aws_access_key_id=conf["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=conf["AWS_SECRET_ACCESS_KEY"],
    )
    return ec2


async def main():
    cf = "aws_acl.yaml"
    conf = None
    if os.path.isfile(cf):
        print("loading config from " + cf, flush=True)
        with open(cf, "r") as f:
            conf = yaml.safe_load(f)
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
            fout.write(
                'AWS_NETWORK_ACL_ID: ""  # Replace with your actual network acl ID\n'
            )
            fout.write('AWS_REGION: ""  # Replace with your AWS region\n')
            fout.write('AWS_ACCESS_KEY_ID: ""  # Replace with your AWS access key\n')
            fout.write(
                'AWS_SECRET_ACCESS_KEY: ""  # Replace with your AWS secret key\n'
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
            if "IntExtIp" in data["targets"]:
                target = data["targets"]["IntExtIp"]
                ext_ip = target["ext_ip"]
            elif "GlobalIp" in data["targets"]:
                target = data["targets"]["GlobalIp"]
                ext_ip = target["ext_ip"]

            print(f"Adding ACL rules for {tag} ALL <-> {ext_ip}")

            try:
                ec2 = prep_ec2(conf, ext_ip)

                response = ec2.describe_network_acls(
                    NetworkAclIds=[conf["AWS_NETWORK_ACL_ID"]]
                )
                network_acls = response["NetworkAcls"]
                rule_number = 101
                for nacl in network_acls:
                    for entry in nacl["Entries"]:
                        if (
                            entry["RuleNumber"] < 32766
                            and entry["RuleNumber"] >= rule_number
                        ):
                            rule_number = entry["RuleNumber"] + 1

                # Add inbound deny rule
                ec2.create_network_acl_entry(
                    NetworkAclId=conf["AWS_NETWORK_ACL_ID"],
                    RuleNumber=rule_number,
                    Protocol="-1",  # All protocols
                    RuleAction="deny",
                    Egress=False,
                    CidrBlock=f"{ext_ip}/32",
                    PortRange={"From": 0, "To": 65535},
                )

                # Add outbound deny rule
                ec2.create_network_acl_entry(
                    NetworkAclId=conf["AWS_NETWORK_ACL_ID"],
                    RuleNumber=rule_number,
                    Protocol="-1",  # All protocols
                    RuleAction="deny",
                    Egress=True,
                    CidrBlock=f"{ext_ip}/32",
                    PortRange={"From": 0, "To": 65535},
                )

                mitigation.set_enabled()
                mitigation.set_user_data({"rule_number": rule_number})
                print(f"Successfully added ACL rules to block {ext_ip} for ALL")
                return mitigation

            except Exception as e:
                print(f"Error adding network ACL rules: {e}")

    async def disable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        if "IntExtIp" in data["targets"] or "GlobalIp" in data["targets"]:
            # tag = data["tag"]
            target = None
            ext_ip = None
            if "IntExtIp" in data["targets"]:
                target = data["targets"]["IntExtIp"]
                ext_ip = target["ext_ip"]
            elif "GlobalIp" in data["targets"]:
                target = data["targets"]["GlobalIp"]
                ext_ip = target["ext_ip"]

            print(f"Removing ACL rules for ALL -> {ext_ip}")
            try:
                ec2 = prep_ec2(conf, ext_ip)
                user_data = mitigation.get_user_data()
                if user_data is None:
                    print("no user_data with rule_number, ignoring")
                    mitigation.set_disabled()
                    return mitigation
                rule_number = user_data["rule_number"]

                # Remove inbound rule
                ec2.delete_network_acl_entry(
                    NetworkAclId=conf["AWS_NETWORK_ACL_ID"],
                    RuleNumber=rule_number,
                    Egress=False,
                )

                # Remove outbound rule
                ec2.delete_network_acl_entry(
                    NetworkAclId=conf["AWS_NETWORK_ACL_ID"],
                    RuleNumber=rule_number,
                    Egress=True,
                )

                mitigation.set_disabled()
                print(f"Successfully removed ACL rules for ALL <-> {ext_ip}")
                return mitigation
            except ClientError as ce:
                if ce.response["Error"]["Code"] == "InvalidNetworkAclEntry.NotFound":
                    print("rule not found in acl, ignoring")
                    mitigation.set_disabled()
                    return mitigation
                print(f"ClientError removing network ACL rules: {ce}")
            except Exception as e:
                print(f"Error removing network ACL rules: {e}")

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
