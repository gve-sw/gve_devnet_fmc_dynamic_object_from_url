# Cisco FMC - Update Dynamic Object from URL

The purpose of this script is to update Firepower Management Center (FMC) dynamic objects from a remote list of IP addresses.

This script will:

- Look up FMC dynamic objects
- Collect list of current dynamic object IP addresses
- Collect list of new addresses via URL
- Compare both lists
- Add new IP addresses from URL list to dynamic object
- Remove any IP addresses in dynamic object that were not found in URL list

## Contacts

- Matt Schmitz (<mattsc@cisco.com>)

## Solution Components

- Cisco Firepower Management Center

> Tested on FMCv300 running v7.4.1

## Installation/Configuration

### **Step 1 - Clone repo**

```bash
git clone https://github.com/gve-sw/gve_devnet_fmc_dynamic_object_from_url
```

### **Step 2 - Install Required Dependencies**

```bash
pip install -r requirements.txt
```

### **Step 3 - Set Environment Variables**

FMC authentication information is provided to the script via environment variables. This can also be provided via a local `.env` file that resides in the same directory as the primary script. A sample of this file has been provided at `.env-sample`.

```text
# FMC Address or hostname (Example: 192.0.2.1 or fmc.corp.local)
FMC_ADDRESS=
# Username with privileges to update dynamic objects via API
FMC_USERNAME=
# Password of above user
FMC_PASSWORD=
```

### **Step 4 - Configure objects and Schedule**

Dynamic object mappings and optional schedule are configured via a `config.yaml` file. A sample of this file has been provided as `sample-config.yaml`.

```yaml
schedule:
  # Uses schedule if set to `true`, otherwise runs once & exits
  enable: true
  # Frequency of scheduled execution, in minutes
  interval: 5
mapping:
  # Name of dynamic object as it appears in FMC
  dynamic_object_list_01: 
    # URL of IP list that correlates with above FMC object
    url: http://some_url.local/iplist.txt
  # Any number of dynamic object to URL mappings can be created
  dynamic_object_list_02:
    url: http://some_other_url.local/iplist.txt

```

## Usage

### **Run Manually**

To test the script, you may wish to execute it manually. Once configured, it can be run with the following command:

```text
python3 update_object_from_url.py
```

### **Docker**

A docker image has been published for this at ghcr.io/gve-sw/gve_devnet_fmc_dynamic_object_from_url

This image can be used by creating the config & .env files as specified above - then providing them to the container image:

```text
docker run --env-file <path-to-env-file> -v <path-to-config.yaml>:/app/config.yaml -d ghcr.io/gve-sw/gve_devnet_fmc_dynamic_object_from_url:latest
```

Alternatively, a `docker-compose.yml` file has been included as well.

## Demo

![IMAGES/demo.gif](IMAGES/demo.gif#center)

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER

<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
