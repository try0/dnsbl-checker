package jp.try0.jlib.dnsbl;

/**
 * Check result.
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblCheckResult {

	public static DnsblCheckResult ok(String ipAddress, String checkTargetDomainName, IDnsblChecker checker) {
		DnsblCheckResult result = new DnsblCheckResult(false, ipAddress, checkTargetDomainName);
		result.checker = checker;
		return result;
	}

	public static DnsblCheckResult ng(String ipAddress, String checkTargetDomainName, String returnIpAddress,
			IDnsblChecker checker) {
		DnsblCheckResult result = new DnsblCheckResult(true, ipAddress, checkTargetDomainName);
		result.checker = checker;
		result.returnIpAddress = returnIpAddress;
		return result;
	}

	/**
	 * Blacklisted or not
	 */
	private final boolean isListed;
	/**
	 * Check target ip
	 */
	private final String checkTargetIpAddress;
	/**
	 * Check target domain name
	 */
	private final String checkTargetDomainName;
	/**
	 * Dns query result ip
	 */
	private String returnIpAddress;
	/**
	 * Checker
	 */
	private IDnsblChecker checker;

	/**
	 * Constructor.
	 *
	 * @param isListed
	 * @param checkTargetIpAddress
	 * @param checkTargetDomainName
	 */
	public DnsblCheckResult(boolean isListed, String checkTargetIpAddress, String checkTargetDomainName) {
		this.isListed = isListed;
		this.checkTargetIpAddress = checkTargetIpAddress;
		this.checkTargetDomainName = checkTargetDomainName;
	}

	public boolean isListed() {
		return isListed;
	}

	public String getCheckTargetIpAddress() {
		return checkTargetIpAddress;
	}

	public String getCheckTargetDomainName() {
		return checkTargetDomainName;
	}

	public IDnsblChecker getChecker() {
		return checker;
	}

	public String getReturnIpAddress() {
		return returnIpAddress;
	}

}