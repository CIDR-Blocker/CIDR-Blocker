<p align="center">
	<img alt="CIDR Blocker" src="assets/img/CIDR_Blocker.png" height="250" width="250">
</p>

<p align="center">
	Blocks CIDR (Classless Inter-Domain Routing) IP Ranges
</p>

<p align="center">
	<a href="https://travis-ci.org/CIDR-Blocker/CIDR-Blocker"><img alt="Travis CI Status" src="https://img.shields.io/travis/CIDR-Blocker/CIDR-Blocker.svg?style=flat-square"></a>
	<a href="https://github.com/CIDR-Blocker/CIDR-Blocker/issues"><img alt="Issues" src="https://img.shields.io/github/issues/CIDR-Blocker/CIDR-Blocker.svg?style=flat-square"></a>
	<img alt="Downloads" src="https://img.shields.io/github/downloads/CIDR-Blocker/CIDR-Blocker/total.svg?style=flat-square">
</p>

---

# ConVar

- **sm_cidr_log** Enable blocked logging [Default: **1.0**] (Min: **0.0**) (Max: **1.0**)

# Database Structure

### CIDR_LIST

- **id** - Auto incremental ID (**Filled in automatically**)

- **cidr** - CIDR to block

- **kick_message** - Message to display when kicked

- **comment** - Helps you keep track

### CIDR_WHITELIST

- **id** - Auto incremental ID (**Filled in automatically**)

- **type** - Whitelist type (**steam** OR **ip**)

- **identity** - Depending on the whitelist type (**steamid32** OR **IP**)

- **comment** - Helps you keep track

### CIDR_LOG (Used when `sm_cidr_log` is **1.0**)

- **id** - Auto incremental ID (**Filled in automatically**)

- **ip** - Client's connecting IP

- **steamid** - Client's SteamID32

- **name** - Client's connecting name

- **cidr** - CIDR that was triggered

- **time** - Time it was blocked

# Installation

1. Extract **CIDR_Blocker.smx** to **/addons/sourcemod/plugins**
2. Create **cidr_blocker** entry in your database.cfg
3. (Optional | Recommended) Import https://github.com/CIDR-Blocker/CIDR-Blocker/blob/master/imports/datacenters.sql into `cidr_list` table


# Download

Download the latest version from the [release](https://github.com/CIDR-Blocker/CIDR-Blocker/releases) page

# Resources

- ASN Blocklist - https://www.enjen.net/asn-blocklist/

- Pre-made SQL script of most datacenters - https://github.com/CIDR-Blocker/CIDR-Blocker/blob/master/imports/datacenters.sql

# License

GPL-3.0

Icon made by <a href="http://www.freepik.com/" target="_blank">Freepik</a> from <a href="http://www.flaticon.com/" target="_blank">http://www.flaticon.com/</a>
