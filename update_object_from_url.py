"""
Copyright (c) 2024 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import logging as log
import os
import sys
from ipaddress import ip_address, ip_network
from time import sleep

import requests
import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from schema import Schema, SchemaError

# Load environment variables
load_dotenv()
FMC = os.getenv("FMC_ADDRESS")
USERNAME = os.getenv("FMC_USERNAME")
PASSWORD = os.getenv("FMC_PASSWORD")

if not FMC or not USERNAME or not PASSWORD:
    log.error("Required environment variables not set. Quitting...")
    sys.exit(1)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Logging setup
log.basicConfig(format="%(asctime)s - %(message)s", level=log.INFO)

# Static URL components for FMC
PLATFORM_URL = "https://" + FMC + "/api/fmc_platform/v1"
CONFIG_URL = "https://" + FMC + "/api/fmc_config/v1"

config_schema = Schema(
    {"schedule": {"enable": bool, "interval": int}, "mapping": {str: {"url": str}}}
)
global config

# Limit paging for FMC items, max is 1000
PAGING_LIMIT = 1000


class FirePower:
    def __init__(self):
        """
        Initialize the FirePower class, log in to FMC,
        and save authentication headers
        """
        with requests.Session() as self.s:
            log.info(f"Attempting login to {FMC}")
            self.authRequest()

            self.headers = {
                "Content-Type": "application/json",
                "X-auth-access-token": self.token,
            }

    def authRequest(self) -> None:
        """
        Authenticate to FMC and retrieve auth token
        """
        authurl = f"{PLATFORM_URL}/auth/generatetoken"
        resp = self.s.post(authurl, auth=(USERNAME, PASSWORD), verify=False)
        if resp.status_code == 204:
            # API token, Refresh token, default domain, and
            # other info returned in HTTP headers
            log.info("Connected to FMC.")
            # Save auth token & global domain UUID
            self.token = resp.headers["X-auth-access-token"]
            self.global_UUID = resp.headers["DOMAIN_UUID"]
            log.info(f"Using global domain UUID: {self.global_UUID}")
            return
        else:
            log.error("Authentication Failed.")
            log.error("Error from FMC: " + resp.text)
            sys.exit(1)

    def getDynamicObjectByName(self, name: str) -> str | None:
        """
        Look up FMC dynamic object UUID by object name
        """
        log.info(f"Looking up dynamic object: {name}...")
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/dynamicobjects"
        url += f"?name={name}"

        resp = self.s.get(url, headers=self.headers, verify=False)

        if resp.status_code == 200:
            if "items" not in resp.json().keys() or len(resp.json()["items"]) == 0:
                log.error(f"Dynamic object {name} not found.")
                return None
            else:
                log.info(
                    f"Found dynamic object {name} with UUID: {resp.json()['items'][0]['id']}"
                )
                return resp.json()["items"][0]["id"]
        else:
            log.error(f"Failed to retrieve dynamic object {name}.")
            log.error("Error from FMC: " + resp.text)
            return None

    def morePagesAvailable(self, paging: dict) -> tuple[bool, int]:
        """
        Check if more pages are available in paginated response
        If so, return next offset
        """
        pass

    def getDynamicObjectMappings(self, name: str, uuid: str) -> list | None:
        """
        Retrieve dynamic object mappings for a given dynamic object UUID
        """
        log.info(f"Retrieving dynamic object mappings for {name}...")
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/dynamicobjects/{uuid}/mappings"
        url += f"?limit={PAGING_LIMIT}"

        resp = self.s.get(url, headers=self.headers, verify=False)

        addresses = []

        while True:
            if resp.status_code == 200:
                if "items" not in resp.json().keys() or len(resp.json()["items"]) == 0:
                    log.error("Done. No addresses found.")
                    return None
                else:
                    addresses += [ip["mapping"] for ip in resp.json()["items"]]
                    if "next" in resp.json()["paging"].keys():
                        url = resp.json()["paging"]["next"][0]
                        resp = self.s.get(url, headers=self.headers, verify=False)
                    else:
                        log.info(f"Done. Collected {len(addresses)} mappings.")
                        return addresses
            else:
                log.error("Failed to retrieve dynamic object mappings.")
                log.error("Error from FMC: " + resp.text)
                return None

    def updateDynamicObjects(self, mapping: dict) -> None:
        """
        Push dynamic object updates to FMC
        """
        # Build payload
        payload = {"add": [], "remove": []}
        for item in mapping:
            toAdd = {"mappings": [], "dynamicObject": {"id": mapping[item]["uuid"]}}
            toRemove = {"mappings": [], "dynamicObject": {"id": mapping[item]["uuid"]}}
            for addr in mapping[item]["add"]:
                toAdd["mappings"].append(addr)
            for addr in mapping[item]["remove"]:
                toRemove["mappings"].append(addr)
            payload["add"].append(toAdd)
            payload["remove"].append(toRemove)

        # Send request to FMC
        log.info("Sending updates to FMC...")
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/dynamicobjectmappings"

        resp = self.s.post(url, headers=self.headers, json=payload, verify=False)

        if resp.status_code == 201:
            log.info("Dynamic object mappings updated successfully.")
        else:
            log.error(
                f"Failed to update dynamic object mappings. Status code: {resp.status_code}"
            )
            log.error(f"Error from FMC: {resp.text}")


def validateAddress(address: str) -> list | None:
    """
    Validate IP address / range
    """
    # Ignore blank lines
    if not address:
        return None

    # Check if valid IPv4 / IPv6 address
    try:
        ip_address(address)
        return [address]
    except ValueError:
        pass

    # Check if valid IPv4 / IPv6 network
    try:
        ip_network(address)
        return [address]
    except ValueError:
        pass

    # Allow for ranges separated by "-"
    if "-" in address:
        try:
            start, end = address.split("-")
            start = int(ip_address(start))
            end = int(ip_address(end))
        except ValueError:
            log.error(f"Invalid IP range: {address}")
            return None
        # If above succeeded, assume range & generate list of IPs
        return [str(ip_address(addr)) for addr in range(start, end)]
    else:
        log.error(f"Invalid IP address: {address}")
        return None


def getIPAddressListFromURL(url: str) -> list | None:
    """
    Retrieve IP address list from a URL
    """
    log.info(f"Retrieving IP address list from {url}")
    addresses = []
    try:
        resp = requests.get(url)
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to retrieve IP address list. Error: {e}")
        return None

    if resp.status_code == 200:
        log.info("Processing IP address list...")
        for address in resp.text.splitlines():
            result = validateAddress(address)
            if result:
                addresses += result
        log.info(f"Done. Found {len(addresses)} addresses.")
    else:
        log.error(
            f"Failed to retrieve IP address list. Status code: {resp.status_code}"
        )
        return None

    return addresses


def generateDiff(current: list, new: list) -> tuple[list, list]:
    """
    Generate list of addresses to add & remove
    """
    if not current and not new:
        log.info("No addresses to add or remove.")
        return [], []
    if not current:
        log.info(
            f"Object has no current addresses, so {len(new)} addresses will be added.."
        )
        return new, []
    if not new:
        # Return nothing to avoid removing all current addresses if new list is empty
        log.info(
            "New address list empty. Skipping to avoid removing all current addresses."
        )
        return [], []

    # Compare current & new lists
    add = list(set(new) - set(current))
    remove = list(set(current) - set(new))

    log.info(f"{len(add)} addresses to add. {len(remove)} addresses to remove.")
    return add, remove


def loadConfig() -> None:
    """
    Load configuration file
    """
    log.info("Loading config file...")
    global config
    with open("./config.yaml", "r") as file:
        # Config load
        config = yaml.safe_load(file)
        try:
            # Config validation
            config_schema.validate(config)
        except SchemaError as e:
            log.error("Failed to validate config.yaml. Error:")
            log.error(f"{e}")
            sys.exit(1)
        log.info("Config loaded!")


def run() -> None:
    """
    Main function to retrieve, compare, and update dynamic objects
    """
    # Create a FirePower object
    fmc = FirePower()

    # Collect Dynamic Object UUIDs
    toRemove = []
    for item in config["mapping"]:
        uuid = fmc.getDynamicObjectByName(item)
        if uuid:
            config["mapping"][item]["uuid"] = uuid
        else:
            toRemove.append(item)

    # Check if any dynamic objects were not found
    if len(toRemove) > 0:
        for item in toRemove:
            log.info(f"Removing invalid object ({item}) from further processing...")
            del config["mapping"][item]

    # Collect current mappings
    for item in config["mapping"]:
        current = fmc.getDynamicObjectMappings(item, config["mapping"][item]["uuid"])
        config["mapping"][item]["current"] = current

    # Collect new mappings
    for item in config["mapping"]:
        new = getIPAddressListFromURL(config["mapping"][item]["url"])
        config["mapping"][item]["new"] = new

    # Compare current & new mappings
    for item in config["mapping"]:
        log.info(f"Generating changes for {item}...")
        add, remove = generateDiff(
            config["mapping"][item]["current"], config["mapping"][item]["new"]
        )
        config["mapping"][item]["add"] = add
        config["mapping"][item]["remove"] = remove

    fmc.updateDynamicObjects(config["mapping"])


def startScheduler(interval: int) -> None:
    """
    Set up background scheduler
    """
    log.info(f"Creating task to run every {interval} minutes...")
    scheduler = BackgroundScheduler()
    scheduler.start()
    trigger = IntervalTrigger(
        minutes=int(interval),
    )
    scheduler.add_job(run, trigger=trigger)
    log.info("Scheduler started & tasks loaded!")
    jobs = scheduler.get_jobs()
    next_runs = [f"> Job: {job.name}, Next run: {job.next_run_time}" for job in jobs]
    log.info(f'Next run times: \n{f"{chr(10)}".join(next_runs)}')

    # Run
    try:
        while True:
            sleep(5)
    except KeyboardInterrupt:
        log.warning("Received shutdown signal...")
        scheduler.shutdown(wait=False)
        log.warning("Shutdown complete")


def setup() -> None:
    """
    Load configuration & start scheduler if enabled
    """
    # Load config & validate schema
    loadConfig()
    global config

    if config["schedule"]["enable"]:
        log.info("Scheduled execution enabled. Starting scheduler...")
        startScheduler(config["schedule"]["interval"])
    else:
        log.info("Scheduled execution disabled. Running once...")
        run()


if __name__ == "__main__":
    setup()
