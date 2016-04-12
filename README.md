# STIX2MISP

STIX2MISP is a simple python script that grabs the pertinent information from a valid STIX 1.2 file and attempts to import the relevant IOC information into MISP.

**FULL DISCLOSURE:** STIX is an ever-evloving and complex platform. While I did my best to pull out the relevant information from the valid STIX samples I frequently see, there is a TON of info that this script leaves out. If you find something you want in MISP that isn't getting grabbed from your STIX files, feel free to submit a PR and I'll be happy to merge it in.

# Requirements
  - PyMISP: https://github.com/MISP/PyMISP
  - python-stix: https://github.com/STIXProject/python-stix

# Usage
Make sure your _misp_url_ and _misp_key_ variables are set in the main call. These are the full URL of your MISP instance and your user's MISP API key. Then just run:
```sh
python stix2misp.py -i <file_name>
```

To see other options, such as tagging:
```sh
python stix2misp.py -h
```

The script will run do its best to output what it sees in the STIX file. The script will create a new event when run. If it runs across the below STIX objects, it will add those objects as attributes to that event in MISP.

  - FileObjectType
    - Filename
    - Size and Path (as comments)
    - Hashes:
        - md5
        - sha1
        - sha256
        - ssdeep (assuming the pull request I sent to PyMISP today gets accepted)
  - MutexObjectType
    - Mutex name
  - WindowsRegistryKeyObjectType
    - Key/Value
  - DomainNameObjectType
    - domain
  - URIObjectType
    - URI
  - EmailMessageObjectType
    - sender/from
    - recipient
    - subject
    - reply_to (as email src)
    - x-originating IP (as ipsrc)
  
The script will also process Incident and Indicator descriptions it finds, combine them into a Incident_Descriptions.txt or Indicator_Descriptions.txt file, and upload those files to the event.

# TO-DO
  - Add support for MISP certificate checking
  - Add src/dst IP support
  - Add basically everything that's important in STIX and is not currently on the above list...
  - Auto-check for STIX v 1.2, and if not seen, use stix-ramrod to make it v 1.2.
