import asyncio
import traceback
from nodal_sdk import Mitigator
from nodal_sdk.mitigator import Mitigation


async def main():
    mitigator = Mitigator("mit", 2000)
    await mitigator.register(
        "127.0.0.1", "http://localhost:8080/api/components/handshake", "mitigator_token"
    )

    async def enable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        if "IntExtIp" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["IntExtIp"]
            int_ip = target["int_ip"]
            ext_ip = target["ext_ip"]

            print(f"Enabling {tag} {int_ip} <-> {ext_ip}")

            mitigation.set_enabled()
            return mitigation
        elif "GlobalIp" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["GlobalIp"]
            ext_ip = target["ext_ip"]

            print(f"Enabling {tag} * <-> {ext_ip}")

            mitigation.set_enabled()
            return mitigation
        elif "Isolation" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["Isolation"]
            mac = target["mac"]

            print(f"Enabling ISOLATE {mac}")

            mitigation.set_enabled()
            return mitigation

    async def disable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        if "IntExtIp" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["IntExtIp"]
            int_ip = target["int_ip"]
            ext_ip = target["ext_ip"]

            print(f"Disabling {tag} {int_ip} <-> {ext_ip}")

            mitigation.set_disabled()
            return mitigation
        elif "GlobalIp" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["GlobalIp"]
            ext_ip = target["ext_ip"]

            print(f"Disabling {tag} * <-> {ext_ip}")

            mitigation.set_disabled()
            return mitigation
        elif "Isolation" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["Isolation"]
            mac = target["mac"]

            print(f"Disabling ISOLATE {mac}")

            mitigation.set_disabled()
            return mitigation

    async def refresh(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        if "IntExtIp" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["IntExtIp"]
            int_ip = target["int_ip"]
            ext_ip = target["ext_ip"]

            print(f"Updating {tag} {int_ip} <-> {ext_ip}")

            mitigation.set_enabled()
            return mitigation
        elif "GlobalIp" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["GlobalIp"]
            ext_ip = target["ext_ip"]

            print(f"Updating {tag} * <-> {ext_ip}")

            mitigation.set_enabled()
            return mitigation
        elif "Isolation" in data["targets"]:
            tag = data["tag"]
            target = data["targets"]["Isolation"]
            mac = target["mac"]

            print(f"Updating ISOLATE {mac}")

            mitigation.set_enabled()
            return mitigation

    while True:
        try:
            await mitigator.handle(enable, disable, refresh)
        except Exception as e:
            traceback.print_exception(e)


if __name__ == "__main__":
    asyncio.run(main())
