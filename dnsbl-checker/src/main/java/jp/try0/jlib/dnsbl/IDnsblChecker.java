package jp.try0.jlib.dnsbl;

import java.util.function.Predicate;

/**
 * Dnsbl checker.
 *
 * @author Ryo Tsunoda
 *
 */
public interface IDnsblChecker extends Predicate<String> {

	/**
	 * Gets checker name.
	 * @return
	 */
	default String getName() {
		return "";
	}

	/**
	 * スパムサーバーか否かを判定します。
	 *
	 * @param mailSeverIpAddress
	 * @return
	 */
	DnsblCheckResult checkIpAddress(String mailSeverIpAddress);

	/**
	 * @see DnsblCheckResult#isListed()
	 */
	@Override
	default boolean test(String t) {
		return checkIpAddress(t).isListed();
	}

}