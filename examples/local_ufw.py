import os
import yaml
import asyncio
import traceback
import subprocess
from nodal_sdk import Mitigator
from nodal_sdk.mitigator import Mitigation


async def main():
    cf = "local_ufw.yaml"
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

            print(f"Adding UFW rules for {tag} {int_ip} <-> {ext_ip}")

            try:
                p = subprocess.run(
                    [
                        "ufw",
                        "route",
                        "deny",
                        "from",
                        int_ip,
                        "to",
                        ext_ip,
                    ],
                    capture_output=True,
                    text=True,
                )

                p = subprocess.run(
                    [
                        "ufw",
                        "route",
                        "deny",
                        "to",
                        int_ip,
                        "from",
                        ext_ip,
                    ],
                    capture_output=True,
                    text=True,
                )

                mitigation.set_enabled()
                print(f"Successfully added UFW rules to block {ext_ip} <-> {int_ip}")
                return mitigation

            except Exception as e:
                print(f"Error adding UFW rules: {e}")

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

            print(f"Removing UFW rules for {int_ip} <-> {ext_ip}")
            try:
                p = subprocess.run(
                    ["ufw", "route", "delete", "deny", "from", int_ip, "to", ext_ip],
                    capture_output=True,
                    text=True,
                )
                p = subprocess.run(
                    ["ufw", "route", "delete", "deny", "to", int_ip, "from", ext_ip],
                    capture_output=True,
                    text=True,
                )

                mitigation.set_disabled()
                print(f"Successfully removed UFW rules for {int_ip} <-> {ext_ip}")
                return mitigation
            except Exception as e:
                print(f"Error removing UFW rules: {e}")

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
