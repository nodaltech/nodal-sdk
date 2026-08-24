import asyncio
import random
from nodal_sdk import Feeder
from nodal_sdk.feeder import EventBuilder
from nodal_sdk.types import DeviceKey


def generate_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


async def main():
    ghost_uri = "http://localhost:8080/api/components/handshake"
    token = "feed_token"

    feeder = Feeder("feed", 4002)
    await feeder.register("127.0.0.1", ghost_uri, token)

    while True:
        descs = [
            "Login failed",
            "Using invalid cert",
            "Login from new location",
            "Trying to access forbidden resources",
        ]

        ips = ["192.168.1.9", "192.168.1.12", "192.168.1.133"]

        desc = random.choice(descs)
        device: DeviceKey = {"Internal": generate_mac()}

        event = EventBuilder(device, desc=desc)
        event.set_internal_peer_ip(random.choice(ips))
        event.set_metadata({"danger": "lowkey"})
        event.set_identity("nathan", "hubspot")
        event.hash_bucket(desc, device)

        print(event.get_data())

        feeder.send("event", event.get_data())

        await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(main())
