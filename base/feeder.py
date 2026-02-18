import asyncio
import random

from nodal_sdk import Feeder
from nodal_sdk.feeder import EventBuilder


def generate_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


async def main():
    ghost_uri = "http://localhost:8080/api/components/handshake"
    token = "feed_token"

    feeder = Feeder("feed", 4002)
    await feeder.register("127.0.0.1", ghost_uri, token)

    while True:
        should_feed = random.random() > 0.5

        if should_feed:
            event = EventBuilder(internal_mac=generate_mac(), desc="acting funny")
            event.set_internal_peer_ip("192.168.1.244")
            event.set_metadata({"danger": "lowkey"})
            event.set_identity("nathan", "hubspot")

            print(event.get_data())

            feeder.send("event", event.get_data())

        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
