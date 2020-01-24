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
 * DNSBLチェッカー<br>
 *
 * Dnsblサービスの一覧：{@link https://www.dnsbl.info/dnsbl-list.php}<br>
 * リスト入りのip確認できる：{@link https://talosintelligence.com/}
 *
 * @see https://www.dnsbl.info/dnsbl-list.php
 * @see https://talosintelligence.com/
 * @see https://ja.wikipedia.org/wiki/DNSBL
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblService implements IDnsblChecker {



	public static enum Catalog implements IDnsblChecker {
		/**
		 *
		 */
		SPAMHAUS(new DnsblService(
				"SPAMHAUS ZEN",
				"zen.spamhaus.org",
				ip -> ip.startsWith("127.0.0"),
				"https://www.spamhaus.org/zen/")),
		/**
		 *
		 */
		BARRACUDA(new DnsblService(
				"Barracuda Reputation Block List",
				"b.barracudacentral.org",
				ip -> ip.equals("127.0.0.2"),
				"http://barracudacentral.org/rbl")),

		;

		static {
			System.out.println(Catalog.class.getName() + " - Please confirm the use agreement of each service by yourself");
		}

		/**
		 * service
		 */
		DnsblService service;

		/**
		 * Constructor.
		 *
		 * @param service
		 */
		Catalog(DnsblService service) {
			this.service = service;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public DnsblCheckResult checkIpAddress(String mailSeverIpAddress) {
			return service.checkIpAddress(mailSeverIpAddress);
		}

	}

	/**
	 * ipアドレスを逆転させます。
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
	 * Dnsbl service web page url
	 */
	public final String serviceWebPageUrl;
	/**
	 * Dnsbl service domain suffix
	 */
	public final String serviceDomainSuffix;
	/**
	 * validater
	 */
	public final Predicate<String> validator;

	/**
	 * コンストラクター
	 *
	 * @param serviceName
	 * @param serviceDomainSuffix
	 * @param validator
	 */
	DnsblService(String serviceName, String serviceDomainSuffix, Predicate<String> validator) {
		this(serviceName, serviceDomainSuffix, validator, "");
	}

	/**
	 * コンストラクター
	 *
	 * @param serviceName
	 * @param serviceDomainSuffix
	 * @param validator
	 * @param serviceWebPageUrl
	 */
	DnsblService(String serviceName, String serviceDomainSuffix, Predicate<String> validator,
			String serviceWebPageUrl) {
		this.serviceName = serviceName;
		this.serviceDomainSuffix = serviceDomainSuffix;
		this.validator = validator;
		this.serviceWebPageUrl = serviceWebPageUrl;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final DnsblCheckResult checkIpAddress(String ipAddress) {

		String checkTargetDomainName = createCheckTargetDomainName(ipAddress);

		try {
			// ドメインからipアドレスを引く
			InetAddress addr = InetAddress.getByName(checkTargetDomainName);
			String hostAddress = addr.getHostAddress();

			// 各サービスの判定処理を実行する
			if (getValidator().test(hostAddress)) {
				return DnsblCheckResult.ng(ipAddress, checkTargetDomainName, hostAddress, this);
			}

		} catch (UnknownHostException ignore) {
			// ドメインが見つからない⇒リストアップされていない
			return DnsblCheckResult.ok(ipAddress, checkTargetDomainName, this);
		}

		// デフォルトOK
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

	public String getServiceWebPageUrl() {
		return serviceWebPageUrl;
	}

	public String getServiceDomainSuffix() {
		return serviceDomainSuffix;
	}

	public Predicate<String> getValidator() {
		return validator;
	}

}
