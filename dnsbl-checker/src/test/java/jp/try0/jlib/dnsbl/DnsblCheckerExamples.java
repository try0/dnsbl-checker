package jp.try0.jlib.dnsbl;

import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

/**
 *
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblCheckerExamples {

	private static final String CHECK_TARGET_IP = "check.target.ip";

	@Test
	public void example() {

		{
			// As java.util.function.Predicate

			DnsblService.Catalog.SPAMHAUS.test(CHECK_TARGET_IP);

			Predicate<String> checker = DnsblService.Catalog.SPAMHAUS.and(DnsblService.Catalog.BARRACUDA);
			checker.test(CHECK_TARGET_IP);
		}

		{
			DnsblChecker checker = DnsblChecker.getDefaultInstance();

			// check all services
			checker.checkIpAddressAll(CHECK_TARGET_IP).forEach(result -> {

			});

			// check services until detect listed in
			DnsblCheckResult result = checker.checkIpAddressAny(CHECK_TARGET_IP);

		}

		{
			DnsblChecker checker = new DnsblChecker();
			checker.addChecker(DnsblService.Catalog.SPAMHAUS, DnsblService.Catalog.BARRACUDA);

			DnsblCheckResult result = checker.checkIpAddressAny(CHECK_TARGET_IP);
		}
	}

}
