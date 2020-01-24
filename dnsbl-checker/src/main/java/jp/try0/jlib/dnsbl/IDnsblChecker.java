package jp.try0.jlib.dnsbl;

import java.util.function.Predicate;

/**
 * Dnsbl checker interface.
 *
 * @author Ryo Tsunoda
 *
 */
public interface IDnsblChecker extends Predicate<String> {

	/**
	 * Gets checker name.
	 *
	 * @return
	 */
	default String getName() {
		return "";
	}

	/**
	 * Check if the IP address is on the blacklist.
	 *
	 * @param ipAddress
	 * @return
	 */
	DnsblCheckResult checkIpAddress(String ipAddress);

	/**
	 * @see DnsblCheckResult#isListed()
	 */
	@Override
	default boolean test(String t) {
		return checkIpAddress(t).isListed();
	}

}