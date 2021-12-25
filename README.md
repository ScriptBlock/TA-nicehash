# Nicehash Add-on For Splunk

This is the Splunk UCC framework package for the Nicehash Add-On For Splunk.  It's not intended to be used directly in splunk.  You must build this source into a Splunk app using the [ucc-gen](https://github.com/splunk/addonfactory-ucc-generator) command.

_However_, the app tgz can be found in the output directory and can be installed directly into Splunk.
==========
# Overview
----------
## Nicehash Add-on For Splunk
* Version: 0.1.0
* Vendor Products: Nicehash
* Visible In Splunk Web: Yes, for configuration of Inputs

Nicehash Add-on For Splunk is a connector that allows Splunk administrators to collect various categories of data from Nicehash.  The data is then sent to Splunk for further analysis and processing.

## Hardware And Software requirements
To install the add-on, you must meet the following requirements
* Splunk platform version 7.1 or later

## Supported Technologies
* Nicehash API
  * At this time only a handful of API endpoints are supported, primarily around RIG performance.


## Data Ingestion Parameters For Nicehash Add-on For Splunk
* Review the Nicehash API documentation: https://www.nicehash.com/docs/
* You will need an orginaztion ID as well as a api secret and key - read the docs, but they can be found and generated here: https://www.nicehash.com/my/settings/keys

### Logging
You can enable various levels of logging 

### Proxy
Proxy is supported.  http/https/socks5 with username and password are supported

