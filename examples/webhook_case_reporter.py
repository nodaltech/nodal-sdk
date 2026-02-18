import os
import asyncio
import time
import yaml
import copy
import traceback
import requests
from typing import Any

from nodal_sdk import Reporter
from nodal_sdk.types import Case, Event


async def main():
    cf = "webhook_case_reporter.yaml"
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
                'WEBHOOK_URL: "http://localhost:8080/report" # Where to POST case info\n'
            )
            fout.write(
                'WEBHOOK_XAPIKEY: "somekey" # API key to add to request headers\n'
            )
        print("wrote config file " + cf + " in local dir, please edit it")
        exit(1)

    reporter = Reporter(conf["COMPONENT_NAME"], conf["LISTEN_PORT"])
    await reporter.register(
        conf["COMPONENT_IP"], conf["GHOST_URL"], conf["COMPONENT_TOKEN"]
    )
    reporter.subscribe_cases()

    async def handle_case(case: Case | Any):
        caseid = case.get("case_id")
        print("reporter received case " + str(caseid) + " at %s" % time.time())
        data = copy.deepcopy(case)

        # you can rearrange things however you want before sending data
        del data["fabric"]  # this is visualization data, not needed
        print(str(data))

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": conf["WEBHOOK_XAPIKEY"],
        }
        try:
            url = conf["WEBHOOK_URL"]
            response = requests.post(url, json=data, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            print(f"Status Code: {response.status_code}")
            print("Response Body:", response.text)
            print("Data successfully sent to webhook.")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while sending the webhook: {e}")

    async def handle_event(event: Event | Any):
        pass

    while True:
        try:
            await reporter.handle(handle_case=handle_case, handle_event=handle_event)
        except Exception as e:
            traceback.print_exception(e)


if __name__ == "__main__":
    asyncio.run(main())
