import asyncio
import time
import traceback
from typing import Any

from nodal_sdk import Reporter
from nodal_sdk.types import Case, Event


async def main():
    ghost_uri = "http://localhost:8080/api/components/handshake"
    token = "report_token"

    reporter = Reporter("rep", 4001)
    await reporter.register("127.0.0.1", ghost_uri, token)
    # Use one of the following if you want to receive cases *OR* events
    # reporter.subscribe_cases()
    # reporter.subscribe_events()
    reporter.subscribe_all()

    async def handle_case(case: Case | Any):
        print("reporter received case at %s" % time.time())
        print(case)

    async def handle_event(event: Event | Any):
        print("reporter received event as %s" % time.time())
        print(event)

    while True:
        try:
            await reporter.handle(handle_case=handle_case, handle_event=handle_event)
        except Exception as e:
            traceback.print_exception(e)


if __name__ == "__main__":
    asyncio.run(main())
