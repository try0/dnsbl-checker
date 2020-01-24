package jp.try0.jlib.dnsbl;

import java.io.Serializable;

/**
 * スパムチェック結果
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblCheckResult implements Serializable {

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
	 * 判定結果
	 */
	private final boolean isListed;
	/**
	 * 監視対象メールサーバーip
	 */
	private final String checkTargetIpAddress;
	/**
	 * ブラックリストサービスで確認するドメイン
	 */
	private final String checkTargetDomainName;
	/**
	 * Aレコード
	 */
	private String returnIpAddress;
	/**
	 * 検出クラス
	 */
	private IDnsblChecker checker;

	/**
	 * コンストラクター
	 *
	 * @param isSpamServer
	 * @param checkTargetIp
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