# Zeek New
Find new things on your network using Zeek. This is an extension of the Zeek New Domains package (which is also included in this package). This package works best on home and small office networks, its performance on busier networks is likely not great.

## New Things Found
* New Domains queried in the last n Hours
* New orig_h -> resp_h pairs
* New HTTP User-Agents 
* New devices (via DHCP)

## Notice Log Additions
* Adds the dhcp hostname of the orig_h in notice log entries (if it is found). This feature doesn't persist across reboots and is still a WIP
