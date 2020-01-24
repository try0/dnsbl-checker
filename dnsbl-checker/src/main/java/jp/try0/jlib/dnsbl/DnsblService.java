package jp.try0.jlib.dnsbl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * DNSBL Service<br>
 * <br>
 *
 * References<br>
 * Dnsbl list：{@link https://www.dnsbl.info/dnsbl-list.php}<br>
 * Spam ip list：{@link https://talosintelligence.com/}
 *
 * @see https://www.dnsbl.info/dnsbl-list.php
 * @see https://talosintelligence.com/
 * @see https://ja.wikipedia.org/wiki/DNSBL
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblService implements IDnsblChecker {

	/**
	 * Dnsbl service catalog.
	 *
	 * @author Ryo Tsunoda
	 *
	 */
	public static enum Catalog implements IDnsblChecker {

	/**
	 * SPAMHAUS ZEN
	 */
	SPAMHAUS(
			new DnsblService("SPAMHAUS ZEN", "zen.spamhaus.org", ip -> ip.startsWith("127.0.0")),
			"https://www.spamhaus.org/zen/"),
	/**
	 * Barracuda Reputation Block List
	 */
	BARRACUDA(
			new DnsblService("Barracuda Reputation Block List", "b.barracudacentral.org", DEFAULT_DETECTOR),
			"http://barracudacentral.org/rbl"),
	/**
	 * SpamCop Blocking List
	 */
	SPAM_COP(
			new DnsblService("SpamCop Blocking List", "bl.spamcop.net", DEFAULT_DETECTOR),
			"https://www.spamcop.net/bl.shtml"),
	/**
	 * LashBack's unsubscribe blacklist
	 */
	LASHBACK(
			new DnsblService("LashBack's unsubscribe blacklist", "ubl.unsubscore.com", DEFAULT_DETECTOR),
			"https://blacklist.lashback.com/"),
	/**
	 * Passive Spam Block List
	 */
	PASSIVE_SPAM_BLOCK_LIST(
			new DnsblService("Passive Spam Block List", "psbl.surriel.com", DEFAULT_DETECTOR),
			"https://psbl.org/"),

		;

		static {
			System.out.println(
					Catalog.class.getName() + " - Please confirm the use agreement of each service by yourself");
		}

		/**
		 * service
		 */
		DnsblService service;

		/**
		 * Dnsbl service web page url
		 */
		public final String serviceWebPageUrl;

		/**
			 * Constructor.
			 *
			 * @param service
			 */
		Catalog(DnsblService service, String serviceWebPageUrl) {
			this.service = service;
			this.serviceWebPageUrl = serviceWebPageUrl;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public DnsblCheckResult checkIpAddress(String mailSeverIpAddress) {
			return service.checkIpAddress(mailSeverIpAddress);
		}

		public String getServiceWebPageUrl() {
			return serviceWebPageUrl;
		}

	}

	public static final Predicate<String> DEFAULT_DETECTOR = ip -> ip.equals("127.0.0.2");

	/**
	 *
	 * @param ipAddress
	 * @return
	 */
	private static String reverseIpAddress(String ipAddress) {
		String[] ipNums = ipAddress.split(Pattern.quote("."));
		Collections.reverse(Arrays.asList(ipNums));
		return Arrays.stream(ipNums).collect(Collectors.joining("."));
	}

	/**
	 * Dnsbl service name
	 */
	public final String serviceName;
	/**
	 * Dnsbl service domain suffix
	 */
	public final String serviceDomainSuffix;
	/**
	 * detector
	 */
	public final Predicate<String> detector;

	/**
	 * Constructor.
	 *
	 * @param serviceName
	 * @param serviceDomainSuffix
	 * @param detector
	 */
	DnsblService(String serviceName, String serviceDomainSuffix, Predicate<String> detector) {
		this.serviceName = serviceName;
		this.serviceDomainSuffix = serviceDomainSuffix;
		this.detector = detector;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final DnsblCheckResult checkIpAddress(String ipAddress) {

		String checkTargetDomainName = createCheckTargetDomainName(ipAddress);

		try {
			InetAddress addr = InetAddress.getByName(checkTargetDomainName);
			String hostAddress = addr.getHostAddress();

			// detect
			if (getDetector().test(hostAddress)) {
				return DnsblCheckResult.ng(ipAddress, checkTargetDomainName, hostAddress, this);
			}

		} catch (UnknownHostException ignore) {
			// Not blacklisted
			return DnsblCheckResult.ok(ipAddress, checkTargetDomainName, this);
		}

		return DnsblCheckResult.ok(ipAddress, checkTargetDomainName, this);
	}

	protected String createCheckTargetDomainName(String ipAddress) {
		return reverseIpAddress(ipAddress) + "." + serviceDomainSuffix;
	}

	@Override
	public String getName() {
		return getServiceName();
	}

	public String getServiceName() {
		return serviceName;
	}

	public String getServiceDomainSuffix() {
		return serviceDomainSuffix;
	}

	public Predicate<String> getDetector() {
		return detector;
	}

}
