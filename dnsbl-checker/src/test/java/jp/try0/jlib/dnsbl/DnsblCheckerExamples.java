package jp.try0.jlib.dnsbl;

import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

/**
 * Usages
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblCheckerExamples {


	private static final String CHECK_TARGET_IP = "127.0.0.1";

	@Test
	@SuppressWarnings("unused")
	public void example() {

		{
			// As a java.util.function.Predicate

			boolean isListedInSpamhausBl = DnsblService.Catalog.SPAMHAUS.test(CHECK_TARGET_IP);

			Predicate<String> detector = DnsblService.Catalog.SPAMHAUS.and(DnsblService.Catalog.BARRACUDA);
			boolean isListedInSpamhausAndBarracudaBl = detector.test(CHECK_TARGET_IP);


		}

		{
			DnsblChecker checker = DnsblChecker.getDefaultInstance();

			// check all services
			checker.checkAll(CHECK_TARGET_IP).forEach(result -> {

			});

			// check services until detect listed in
			DnsblCheckResult result = checker.checkAny(CHECK_TARGET_IP);

		}

		{
			DnsblChecker customChecker = new DnsblChecker();
			customChecker.addCheckers(DnsblService.Catalog.SPAMHAUS, DnsblService.Catalog.BARRACUDA);

			DnsblCheckResult result = customChecker.checkAny(CHECK_TARGET_IP);
		}

		{
			for(IDnsblChecker checker : DnsblService.Catalog.values()) {

				DnsblCheckResult result = checker.checkIpAddress(CHECK_TARGET_IP);
				System.out.println(checker.getName());
				System.out.println(CHECK_TARGET_IP);
				System.out.println(result.getCheckTargetDomainName());
				System.out.println(result.getReturnIpAddress());

				System.out.println();
			}
		}
	}

}
