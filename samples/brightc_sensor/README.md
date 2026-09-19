# BrightC Sensor Enterprise MIB Definition

This directory contains `DAECGE-BRIGHTC-MIB.txt`, an example Enterprise MIB definition demonstrating how private enterprise MIBs (under `iso.org.dod.internet.private.enterprises`) are defined and mapped in Zephyr SNMP agent applications.

To load this MIB in your local Net-SNMP tools:

```bash
cp DAECGE-BRIGHTC-MIB.txt ~/.snmp/mibs/
export MIBS=+DAECGE-BRIGHTC-MIB
```
