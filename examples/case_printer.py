import os
import asyncio
import time
import yaml
import traceback
from typing import Any

from nodal_sdk import Reporter
from nodal_sdk.types import Case, Event


async def main():
    cf = "case_printer.yaml"
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

    reporter = Reporter(conf["COMPONENT_NAME"], conf["LISTEN_PORT"])
    await reporter.register(
        conf["COMPONENT_IP"], conf["GHOST_URL"], conf["COMPONENT_TOKEN"]
    )
    reporter.subscribe_cases()

    async def handle_case(case: Case | Any):
        print("reporter received case at %s" % time.time())
        print(case)

    async def handle_event(event: Event | Any):
        pass

    while True:
        try:
            await reporter.handle(handle_case=handle_case, handle_event=handle_event)
        except Exception as e:
            traceback.print_exception(e)


if __name__ == "__main__":
    asyncio.run(main())
