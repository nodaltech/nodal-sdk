import os
import json
import logging
import time
import yaml
import traceback
import requests
import copy
import psycopg
from queue import Queue
from threading import Thread
from flask import Flask, request
from langchain.agents import create_agent

MAX_CHAINS = 3  # we're only going to research the top 3 C2 chains of each case
GHOST_CONFIG_INTERVAL = (
    30.0  # wait at least this long before pulling ghost config again
)
ANON_PREFIX = "dv_"  # beginning of every anonymous substitute value, so we can find them in AI responses
ANON_SUFFIX = "c"  # end of every anonymous substitute value, so we can easily replace them in responses

ci = None
app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


class CaseInvestigator(Thread):

    def __init__(self):
        super().__init__()
        self.conf = None
        self.work = Queue()
        self.id_subs = {}  # for storing and lookup of substitutes for anonymized ID's
        self.sub_ids = {}  # for looking up an original ID using the substitute
        self.setup()

        # will come from ghost defcon config: minimum interval for invoking Defender agent
        #    and max mitigations Defender is allowed to request, per invocation
        self.agentic_interval_secs = None
        self.agentic_mitigations_per_interval = None
        self.identity_mitigations = None
        self.device_isolations = None

    def run(self):
        investigated_cases = (
            set()
        )  # case_id's are added to this so we avoid working them twice
        last_config_pull = None  # track last time we pulled the config from the ghost
        last_defender_run = (
            None  # track last time we showed our situation to the defender agent
        )

        while True:
            c = self.work.get(
                block=True
            )  # no Investigator or Defender activity unless there is a new case
            case_id = c["case_id"]
            print("ci got case: " + case_id + " ... ", end="")

            # don't go further if case is closed
            if c["closed"]:
                print("closed")
                continue

            invoke_defender = False
            # investigate the case if it's an Activity type and has a NS_IP
            # also only invoke Network Defender after these types of case happen
            ns_ip = c.get("ns_ip")
            if ns_ip != None and len(ns_ip) > 0 and c["variant"] == "Activity":
                if case_id in investigated_cases:
                    print("already investigated")
                else:
                    print("INVESTIGATING, has " + str(len(c["events"])) + " events...")
                    self.investigate_case(c)
                    investigated_cases.add(case_id)
                    invoke_defender = True
            else:
                print("no ns_ip or not activity variant...")

            if not(invoke_defender):
                continue

            # the rest has to do with Network Defender
            # sleep a little bit to make sure ghost db is not busy with the case
            # this is not needed in proper environment where there is a read-only postgresql replica of ghost db
            time.sleep(15.0)

            # pull the ghost defcon config if it's been a while
            if (
                last_config_pull is None
                or last_config_pull + GHOST_CONFIG_INTERVAL < time.time()
            ):
                self.pull_defcon()
                last_config_pull = time.time()

            # prepare a situation dump for the Defender agent and invoke it, if it's time
            if self.agentic_interval_secs > 0:
                if (
                    last_defender_run is None
                    or last_defender_run + self.agentic_interval_secs < time.time()
                ):
                    print("INVOKING DEFENDER...")
                    self.invoke_defender(
                        c
                    )  # pass the current case, we can add Defender notes to it
                    last_defender_run = time.time()

    def invoke_defender(self, recent_case):
        """Prepare a full situation awareness report for Claude and allow it to ask for mitigations"""
        # clear out the anonymization substitutes from the last time
        self.reset_anons()

        # get the devices most likely to be involved in an attack
        important_devs = self.ghost_fetch("devices/categorical", "")
        devs = {}
        for dev in important_devs["data"]:
            if dev["internal"]:
                devs[dev["device_id"]] = {"metadata": dev["metadata"]}
        print(str(devs))

        # set up a DB connection to the ghost DB
        ghost_config = self.ghost_fetch("config", "")
        connstr = "dbname=" + ghost_config["db_name"]
        connstr += " host=" + ghost_config["db_host"]
        connstr += " port=" + str(ghost_config["db_port"])
        connstr += " user=" + ghost_config["db_user"]
        connstr += " password=" + ghost_config["db_pass"]
        events = None
        chains = None
        case_chains = None
        with psycopg.connect(connstr) as conn:

            # get the events for each device from the last two days
            devs_in = None
            for devkey in devs.keys():
                if devs_in is None:
                    devs_in = "'" + devkey + "'"
                else:
                    devs_in += ", '" + devkey + "'"

            with conn.cursor() as cur:
                sql = "SELECT device, peer, peer_ip, description, trigger_packet, identity, "
                sql += "TO_CHAR(ts, 'YYYY-MM-DD HH24:MI:SS.MS') as tsf "
                sql += "FROM events where ts > NOW() - INTERVAL '2 DAY' "
                sql += "AND device IN (" + devs_in + ") "
                sql += "ORDER BY ts LIMIT 1000"
                cur.execute(sql)
                events = cur.fetchall()

            # get the ambient chains for the last two days
            with conn.cursor() as cur:
                sql = "SELECT device_ids, average, "
                sql += "TO_CHAR(ts, 'YYYY-MM-DD HH24:MI:SS.MS') as tsf "
                sql += "FROM chains where ts > NOW() - INTERVAL '2 DAY' "
                sql += "ORDER BY ts LIMIT 1000"
                cur.execute(sql)
                chains = cur.fetchall()

            # get all chains associated with cases involving important devices, for the last five days
            with conn.cursor() as cur:
                sql = "SELECT a.c2_chain, a.average, "
                sql += "TO_CHAR(a.ts, 'YYYY-MM-DD HH24:MI:SS.MS') as tsf "
                sql += "FROM inferences a "
                sql += "INNER JOIN cases_inferences_jct b ON a.inference_id = b.inference_id "
                sql += "INNER JOIN cases c on b.case_id = c.case_id "
                sql += "WHERE a.ts > NOW() - INTERVAL '5 DAY' "
                sql += "AND c.mac IN (" + devs_in + ") "
                sql += "ORDER BY a.ts LIMIT 1000"
                cur.execute(sql)
                case_chains = cur.fetchall()

        # Make a text narrative from the events
        event_text = "List of possible security events:\n"
        for ev in events:
            description = ev[3]
            if description.startswith("SSH"):
                continue
            event_text += "At " + ev[6] + " "
            event_text += "device " + self.anonymize(ev[0]) + " "
            event_text += description + " involving device "
            event_text += self.anonymize(ev[1]) + " "
            if ev[4] != None:
                tp = ev[4]["transport"]
                event_text += "indicated by packet of size " + str(ev[4]["size"])
                if "protocol" in tp:
                    event_text += ", protocol " + tp["protocol"]
                    if "src_port" in tp:
                        event_text += ", source port " + str(tp["src_port"])
                        event_text += ", dest port " + str(tp["dest_port"])
            event_text += "\n"

        # Add on a narrative about ambient C2 chains but only the ones involving our important devices
        event_text += "\nList of possible C2 channels not associated with cases:\n"
        for chain in chains:
            device_ids = chain[0]
            confidence = chain[1]
            if confidence < 0.3 or len(device_ids) < 3:
                continue

            include = False
            for devid in device_ids:
                if devid in devs:
                    include = True
                    break

            if include:
                event_text += "At " + chain[2] + " "
                for i in range(0, len(device_ids)):
                    if i == len(device_ids) - 1:
                        event_text += "(IP " + device_ids[i] + ")"
                    elif i == 0:
                        event_text += (
                            "(device " + self.anonymize(device_ids[i]) + ") <-> "
                        )
                    else:
                        event_text += (
                            "(device " + self.anonymize(device_ids[i]) + ") <-> "
                        )
                event_text += (
                    ", overall detection confidence " + str(round(confidence, 4)) + "\n"
                )

        # Add on a narrative about case C2 chains
        event_text += "\nList of possible C2 channels associated with cases:\n"
        for chain in case_chains:
            inf = chain[0]
            confidence = chain[1]
            if confidence < 0.2:
                continue

            for devs in chain[0]:
                if "External" in devs[0]:
                    event_text += "(IP " + devs[0]["External"] + ")"
                else:
                    event_text += (
                        "(device " + self.anonymize(devs[0]["Internal"]) + ") <-> "
                    )
            event_text += (
                ", overall detection confidence " + str(round(confidence, 4)) + "\n"
            )

        question_text = "Here is a report of potentially interesting security events and possible hacker C2 channels, "
        question_text += "from the past several days. Tools are also provided for researching external IP addresses, and "
        question_text += "for blocking a given external IP address from communicating with devices inside the perimeter.\n\n"
        question_text += "You are only allowed to ask for up to " + str(
            self.agentic_mitigations_per_interval
        )
        question_text += " blocks, so prioritize them and ask for only the ones that are most likely to disrupt an attack."
        question_text += " Don't block an address if isn't involved with a device that appears from the events to be "
        question_text += "used by hackers for lateral movement, exfiltration, or other malicious activities.\n\n"
        question_text += "In 50 words or fewer, summarize whether you think hackers are inside the network and the "
        question_text += "actions you took to block their C2.\n\n"
        question_text += event_text
        print(question_text)
        AIMsg3 = self.deanon(self.ask_agent(question_text, self.defender_agent))
        self.add_note(recent_case["case_id"], "Claude defender report: " + str(AIMsg3))

    def investigate_case(self, c):
        """Add macaddress.io, VirusTotal IP lookup, and Claude analyst agent info as notes to case"""
        # clear out the anonymization substitutes from the last time
        self.peer_anons = {}

        case_id = c["case_id"]

        # get virustotal report, add to case_text, add back to case as note
        vtrep = ""
        chain_count = 0
        for inf in c["inferences"]:
            outside_host = inf["c2_chain"][-1][0]["External"]
            vtrep += self.get_ip_report(outside_host) + "\n"
            chain_count += 1
            if chain_count == MAX_CHAINS:
                break
        self.add_note(case_id, vtrep)

        # get manufacturer info from mac and add to text and case notes
        mac = c["mac"]
        macrep = self.get_manufacturer(mac)
        self.add_note(case_id, macrep)

        # let's see what Claude thinks of just the events, and add as a note
        # self.events_to_text() and self.chains_to_text() consistently anonymize all mac's
        question_text = "A device within the company's internal network caused the following events:\n"
        event_text = self.events_to_text(c)
        print(event_text)
        question_text += event_text
        question_text += "\nIn 50 words or fewer, what's going on and is it malicious?"
        AIMsg1 = self.deanon(self.ask_agent(question_text, self.investigator_agent))
        self.add_note(case_id, "Claude event analysis: " + str(AIMsg1))

        # let's see what Claude thinks of the events + the potential C2 chains + the other info
        question_text = "A device (the Actor) within the company's internal network caused some potential security events.\n"
        question_text += (
            "Information about the device's mac address (" + macrep + ").\n\n"
        )
        question_text += "The events that triggered this investigation:\n"
        question_text += event_text + "\n\n"
        question_text += "Possible C2 channels into the device were:\n"
        chain_text = self.chains_to_text(c)
        print(chain_text)
        question_text += chain_text + "\n\n"
        question_text += (
            "VirusTotal IP research about possible C2 channel external hosts:\n"
        )
        question_text += vtrep + "\n\n"
        question_text += "\nIn 50 words or fewer, what should be done now?"
        AIMsg2 = self.deanon(self.ask_agent(question_text, self.investigator_agent))
        self.add_note(case_id, "Claude suggested actions: " + str(AIMsg2))

        # if we want to send the whole case to a ticketing system
        # we can make it more readable but leave all the mac's, IP's, etc.
        clean_case = self.clean_case(c)
        case_text = json.dumps(clean_case, indent=4)
        case_text += "\n\n" + vtrep
        case_text += "\n\n" + macrep
        case_text += "\n\n" + "Claude event analysis: " + AIMsg1
        case_text += "\n\n" + "Claude suggested actions: " + AIMsg2
        # now send it somewhere...
        # you also may want to call out to PagerDuty or some other alert mechanism
        # this is the right place to do things only for the most important cases,
        #    and only once per case

    def ask_agent(self, question_text, agent):
        """Send a question to the AI agent and return its answer"""
        result = agent.invoke(
            {"messages": [{"role": "user", "content": question_text}]}
        )
        AIMsg = "n/a"
        last_ai_message = next(
            m for m in reversed(result["messages"]) if m.type == "ai"
        )
        if last_ai_message != None:
            AIMsg = last_ai_message.content
        return AIMsg

    def anonymize(self, peer_key):
        """Return the same anonymous string substitute for a given string"""
        peer_sub = self.id_subs.get(peer_key)
        if peer_sub is None:
            peer_sub = ANON_PREFIX + str(len(self.id_subs) + 1) + ANON_SUFFIX
            self.id_subs[peer_key] = peer_sub
            self.sub_ids[peer_sub] = peer_key
        return peer_sub

    def deanon(self, text):
        """Replace all anonymous substitutes in the text with the original values"""
        left_text = ""
        right_text = text
        while True:
            start_ind = right_text.find(ANON_PREFIX)
            if start_ind == -1:
                break
            end_ind = right_text.find(ANON_SUFFIX, start_ind + len(ANON_PREFIX))
            if end_ind == -1:
                break
            sub = right_text[start_ind : end_ind + 1]
            orig = self.sub_ids.get(sub)
            if orig is None:
                orig = sub
            left_text += right_text[:start_ind] + orig
            if end_ind == len(right_text) - 1:
                right_text = ""
                break
            else:
                right_text = right_text[end_ind + 1 :]
        return left_text + right_text

    def reset_anons(self):
        """Reset the anonymization dicts"""
        self.id_subs = {}
        self.sub_ids = {}

    def events_to_text(self, case):
        """Construct anonymized text narrative out of the list of events of a Case"""
        prev_ts = None
        event_text = ""
        for ev in sorted(case["events"], key=lambda x: x["ts"]):
            if prev_ts != None:
                s = round(ev["ts"] - prev_ts, 3)
                event_text += str(s) + " seconds later, "
            peer_loc = "internal"
            peer_key = None
            if "External" in ev["peer"]:
                peer_loc = "external"
                peer_key = ev["peer"]["External"]
            else:
                peer_key = ev["peer"]["Internal"]
            peer_sub = self.anonymize(peer_key)
            event_text += (
                ev["description"] + " involving " + peer_loc + " device " + peer_sub
            )
            tp = ev["trigger_packet"]["transport"]
            event_text += " indicated by a packet of size " + str(
                ev["trigger_packet"]["size"]
            )
            if "protocol" in tp:
                event_text += ", protocol " + tp["protocol"]
                if "src_port" in tp:
                    event_text += ", source port " + str(tp["src_port"])
                    event_text += ", dest port " + str(tp["dest_port"])
            event_text += ";\n"
            prev_ts = ev["ts"]
        return event_text

    def chains_to_text(self, c):
        """Construct anonymized text narrative out of the list of possible C2 chains"""
        chain_text = ""
        chain_count = 0
        for inf in c["inferences"]:
            for devs in inf["c2_chain"]:
                if "External" in devs[0]:
                    chain_text += "(external IP " + devs[0]["External"] + ")"
                else:
                    chain_text += (
                        "(internal device "
                        + self.anonymize(devs[0]["Internal"])
                        + ") <-> "
                    )
            chain_text += (
                ", overall detection confidence " + str(round(inf["average"], 4)) + "\n"
            )
            chain_count += 1
            if chain_count == MAX_CHAINS:
                break
        return chain_text

    def clean_case(self, case):
        """Clean extra data out of Case json that human analyst won't want"""
        c = copy.deepcopy(case)
        del c["fabric"]
        del c["expiry"]
        del c["closed"]
        evid = 1
        for ev in c["events"]:
            ev["event_id"] = evid  # replace long guid with short index
            evid += 1
            if "trigger_packet" in ev:
                del ev["trigger_packet"]["lifecycle"]
        if len(c["inferences"]) > 3:
            c["inferences"] = c["inferences"][0:3]
        for inf in c["inferences"]:
            del inf["histogram"]
            del inf["inference_id"]
            del inf["ts"]
            for ci in range(0, len(inf["c2_chain"])):
                inf["c2_chain"][ci] = inf["c2_chain"][ci][0]
        return c

    def pull_defcon(self):
        """Fetch ghost defcon config from ghost REST API"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.conf["GHOST_APIKEY"],
        }
        try:
            url = self.conf["GHOST_URI"] + "/api/config/defcon"
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            rj = response.json()
            self.agentic_interval_secs = rj["agentic_interval_secs"]
            self.agentic_mitigations_per_interval = rj[
                "agentic_mitigations_per_interval"
            ]
            self.identity_mitigations = rj["identity_mitigations"]
            self.device_isolations = rj["device_isolations"]
        except requests.exceptions.RequestException as e:
            print(f"error fetching defcon: {e}")

    def ghost_fetch(self, entity, query_string):
        """Fetch records from ghost REST API"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.conf["GHOST_APIKEY"],
        }
        try:
            url = self.conf["GHOST_URI"] + "/api/" + entity + "?" + query_string
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"error adding note: {e}")
        return None

    def add_note(self, case_id, note):
        """Add a string as a note on a Case, using ghost REST API"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.conf["GHOST_APIKEY"],
        }
        try:
            url = self.conf["GHOST_URI"] + "/api/notes"
            nd = {
                "relation": "cases",
                "relation_id": case_id,
                "note": note,
                "metadata": {},
            }
            response = requests.post(url, headers=headers, json=nd)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            print(f"error adding note: {e}")

    def block_external_ip(self, ip_address: str):
        """Block an ip address from communicating with any internal device"""
        print("!!! Block called for " + ip_address)

    def get_ip_report(self, ip_address: str) -> str:
        """Look up reputation and danger information about an ip address from virus total threat intel"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.conf["VIRUSTOTAL_APIKEY"],
        }
        result = ""
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                result += f"VirusTotal for {ip_address}: "
                result += f"Country {data.get('country', 'N/A')}, "
                result += f"Owner(ASN) {data.get('as_owner', 'N/A')}, "
                result += f"RepScore {data.get('reputation', 0)}, "
                result += f"MalDetect {malicious_count}/{total_engines}"
            elif response.status_code == 404:
                result += (
                    f"Error: IP address {ip_address} not found in VirusTotal database."
                )
            elif response.status_code == 401:
                result += "Error: Invalid API key."
            else:
                result += f"Error: Received status code {response.status_code}"
        except requests.exceptions.RequestException as e:
            result += f"An error occurred: {e}"
        print("vt called for " + ip_address)
        return result

    def get_manufacturer(self, mac):
        """Look up manufacturer and other information about a mac from macaddress.io"""
        url = f"https://api.macaddress.io/v1?output=json&search={mac}"
        headers = {
            "accept": "application/json",
            "X-Authentication-Token": self.conf["MACADDRESS_APIKEY"],
        }
        result = ""
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                rj = response.json()
                result += "macaddress.io for " + mac + " - "
                result += "Company " + rj["vendorDetails"]["companyName"] + ", "
                result += "Address " + rj["vendorDetails"]["companyAddress"] + ", "
                result += "Country " + rj["vendorDetails"]["countryCode"] + ", "
                result += "VM " + rj["macAddressDetails"]["virtualMachine"] + ", "
            else:
                result += f"Error: Received status code {response.status_code}"
        except Exception as e:
            result += f"An error occurred: {e}"
        print("macaddress.io called for " + mac)
        return result

    def setup(self):
        cf = "CaseInvestigator.yaml"
        if os.path.isfile(cf):
            print("loading config from " + cf, flush=True)
            with open(cf, "r") as f:
                self.conf = yaml.safe_load(f)
        else:
            with open(cf, "w") as fout:
                fout.write(
                    'GHOST_URI: "https://demo.nodal.ninja" # usually https://<ghost fqdn>\n'
                )
                fout.write(
                    'GHOST_APIKEY: "somekey" # API key to add to request headers\n'
                )
                fout.write(
                    'ANTHROPIC_APIKEY: "somekey" # API key for langchain to hit claude\n'
                )
                fout.write('VIRUSTOTAL_APIKEY: "somekey" # API key for Virus Total\n')
                fout.write('MACADDRESS_APIKEY: "somekey" # API key for macaddress.io\n')
                fout.write(
                    "WEBHOOK_LISTEN_PORT: 8090  # port on which to listen for case webhooks\n"
                )
            print("wrote config file " + cf + " in local dir, please edit it")
            exit(1)

        os.environ["ANTHROPIC_API_KEY"] = self.conf["ANTHROPIC_APIKEY"]
        self.investigator_agent = create_agent(
            model="claude-sonnet-4-5-20250929",
            # tools=[self.get_ip_report],
            system_prompt="You are a cyber security analyst investigating recent activity",
        )
        self.defender_agent = create_agent(
            model="claude-sonnet-4-5-20250929",
            tools=[self.get_ip_report, self.block_external_ip],
            system_prompt="You are a SOC team defending the internal network from attackers",
        )


@app.route("/case", methods=["POST"])
def case():
    data = request.get_json()
    ci.work.put(data)
    return {}, 200


if __name__ == "__main__":
    ci = CaseInvestigator()
    ci.start()
    app.run(host="0.0.0.0", port=ci.conf["WEBHOOK_LISTEN_PORT"])
