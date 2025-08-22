# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

## Installation

```bash
dart pub add ip2proxy
```

## Sample Codes

### Query proxy information from BIN database

You can query the proxy information from the IP2Proxy BIN database as below:

```dart
import 'package:ip2proxy/ip2proxy.dart';
import 'package:ip2proxy/src/proxy_result.dart';

Future<void> main() async {
  var dbFile =
      r'C:\your_folder\IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER-FRAUDSCORE.BIN';
  IP2Proxy ipx = IP2Proxy(databasePath: dbFile);
  var ip = '8.8.8.8';

  ProxyResult result = await ipx.getAll(ip);

  print('version: ${IP2Proxy.apiVersion()}');
  print('packageVersion: ${ipx.packageVersion()}');
  print('databaseVersion: ${ipx.databaseVersion()}');
  print('ipAddress: ${result.ipAddress}');
  print('isProxy: ${result.isProxy}');
  print('proxyType: ${result.proxyType}');
  print('countryShort: ${result.countryShort}');
  print('countryLong: ${result.countryLong}');
  print('region: ${result.region}');
  print('city: ${result.city}');
  print('isp: ${result.isp}');
  print('domain: ${result.domain}');
  print('usageType: ${result.usageType}');
  print('asn: ${result.asn}');
  print('asName: ${result.asName}');
  print('lastSeen: ${result.lastSeen}');
  print('threat: ${result.threat}');
  print('provider: ${result.provider}');
  print('fraudScore: ${result.fraudScore}');
}
```