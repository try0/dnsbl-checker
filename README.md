# dnsbl-checker
DNSBL (DNS-Based Black List) checker. 


[Examples](https://github.com/try0/dnsbl-checker/blob/master/dnsbl-checker/src/test/java/jp/try0/jlib/dnsbl/DnsblCheckerExamples.java)


```java
// As a java.util.function.Predicate

boolean isListedInSpamhausBl = DnsblService.Catalog.SPAMHAUS.test(CHECK_TARGET_IP);

Predicate<String> detector = DnsblService.Catalog.SPAMHAUS.and(DnsblService.Catalog.BARRACUDA);
boolean isListedInSpamhausAndBarracudaBl = detector.test(CHECK_TARGET_IP);
```
<br>


```java
DnsblChecker checker = DnsblChecker.getDefaultInstance();

// check all services
checker.checkAll(CHECK_TARGET_IP).forEach(result -> {

});

// check services until detected
DnsblCheckResult result = checker.checkAny(CHECK_TARGET_IP);
```
<br>


```java
DnsblChecker customChecker = new DnsblChecker();
customChecker.addCheckers(DnsblService.Catalog.SPAMHAUS, DnsblService.Catalog.BARRACUDA);

DnsblCheckResult result = customChecker.checkAny(CHECK_TARGET_IP);
```
