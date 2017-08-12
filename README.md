# CIDR Blocker [![Build Status](https://travis-ci.org/RumbleFrog/CIDR-Blocker.svg?branch=master)](https://travis-ci.org/RumbleFrog/CIDR-Blocker)
Blocks CIDR (Classless Inter-Domain Routing) IP Ranges

# ConVar

**sm_cidr_log** Enable blocked logging [Default: **1.0**] (Min: **0.0**) (Max: **1.0**)

# Database Structure

### CIDR_LIST

**id** - Auto incremental ID (**Filled in automatically**)

**cidr** - CIDR to block

**kick_message** - Message to display when kicked

**comment** - Helps you keep track

### CIDR_WHITELIST

**id** - Auto incremental ID (**Filled in automatically**)

**type** - Whitelist type (**steam** OR **ip**)

**identity** - Depending on the whitelist type (**steamid32** OR **IP**)

**comment** - Helps you keep track

### CIDR_LOG (Used when `sm_cidr_log` is **1.0**)

**id** - Auto incremental ID (**Filled in automatically**)

**ip** - Client's connecting IP

**steamid** - Client's SteamID32

**name** - Client's connecting name

**cidr** - CIDR that was triggered

**time** - Time it was blocked

# Installation

1. Extract **CIDR_Blocker.smx** to **/addons/sourcemod/plugins**
2. Create **cidr_blocker** entry in your database.cfg
3. (Optional) Import https://github.com/RumbleFrog/CIDR-Blocker/blob/master/imports/datacenters.sql into `cidr_list` table


# Download 

Download the latest version from the [release](https://github.com/RumbleFrog/CIDR-Blocker/releases) page

# Resources

- ASN Blocklist - https://www.enjen.net/asn-blocklist/

- Pre-made SQL script of most datacenters - https://github.com/RumbleFrog/CIDR-Blocker/blob/master/imports/datacenters.sql

# License

GPL-3.0
