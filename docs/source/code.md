# IP2Proxy Dart API

## IP2Proxy Class

```{py:class} IP2Proxy(databasePath)
Initiate IP2Proxy class.

:param String databasePath: (Required) The file path links to IP2Proxy BIN databases.
```

```{py:function} getAll(ipAddress)
Retrieve proxy information for an IP address.

:param String ipAddress: (Required) The IP address (IPv4 or IPv6).
:return: Returns the proxy information in an object. Refer below table for the fields avaliable in the object
:rtype: object

**RETURN FIELDS**

| Field Name       | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| isProxy    |     Determine whether if an IP address was a proxy or not. Returns 0 is not proxy, 1 if proxy, and 2 if it's data center IP |
| countryShort    |     Two-character country code based on ISO 3166. |
| countryLong    |     Country name based on ISO 3166. |
| region     |     Region or state name. |
| city       |     City name. |
| isp            |     Internet Service Provider or company\'s name. |
| domain         |     Internet domain name associated with IP address range. |
| usageType      |     Usage type classification of ISP or company. |
| asn            |     Autonomous system number (ASN). |
| asName             |     Autonomous system (AS) name. |
| lastSeen       |     Proxy last seen in days. |
| threat         |     Security threat reported. |
| proxyType      |     Type of proxy. |
| provider       |     Name of VPN provider if available. |
| fraudScore       |     Potential risk score (0 - 99) associated with IP address. |
```
