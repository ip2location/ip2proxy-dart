/// Stores the proxy results.
class ProxyResult {
  static const String invalidAddress = 'Invalid IP address.';
  static const String missingFile = 'Invalid database file.';
  static const String notSupported =
      'This parameter is unavailable for selected data file. Please upgrade the data file.';
  static const String invalidBin =
      'Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file.';
  static const String ipv6NotSupported = 'IPv6 address missing in IPv4 BIN.';

  late String ipAddress;
  int? isProxy;
  String? proxyType;
  String? countryShort;
  String? countryLong;
  String? region;
  String? city;
  String? isp;
  String? domain;
  String? usageType;
  String? asn;
  String? asName;
  String? lastSeen;
  String? threat;
  String? provider;
  String? fraudScore;

  ProxyResult(this.ipAddress);

  /// Loads all String fields with error [message].
  void loadMessage(String message) {
    isProxy = -1;
    proxyType = message;
    countryShort = message;
    countryLong = message;
    region = message;
    city = message;
    isp = message;
    domain = message;
    usageType = message;
    asn = message;
    asName = message;
    lastSeen = message;
    threat = message;
    provider = message;
    fraudScore = message;
  }

  @override
  String toString() {
    return '''
ProxyResult(
  ipAddress: $ipAddress,
  isProxy: $isProxy,
  proxyType: $proxyType,
  countryShort: $countryShort,
  countryLong: $countryLong,
  region: $region,
  city: $city,
  isp: $isp,
  domain: $domain,
  usageType: $usageType,
  asn: $asn,
  asName: $asName
  lastSeen: $lastSeen
  threat: $threat
  provider: $provider
  fraudScore: $fraudScore
)''';
  }
}
