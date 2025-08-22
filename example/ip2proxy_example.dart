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
