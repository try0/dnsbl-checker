package jp.try0.jlib.dnsbl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
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
	SPAMHAUS(new DnsblService(
			"SPAMHAUS ZEN",
			"zen.spamhaus.org",
			ip -> ip.startsWith("127.0.0")),
			"https://www.spamhaus.org/zen/"),
	/**
	 * Barracuda Reputation Block List
	 */
	BARRACUDA(new DnsblService(
			"Barracuda Reputation Block List",
			"b.barracudacentral.org",
			ip -> ip.equals("127.0.0.2")),
			"http://barracudacentral.org/rbl"),

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

	/**
	 *
	 * @param ipAddress
	 * @return
	 */
	private static String reverseIpAddress(String ipAddress) {
		List<String> ipNums = Arrays.asList(ipAddress.split(Pattern.quote(".")));
		Collections.reverse(ipNums);
		return ipNums.stream().collect(Collectors.joining("."));
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
