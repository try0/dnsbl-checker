package jp.try0.jlib.dnsbl;

import java.util.ArrayList;
import java.util.List;

/**
 * DNSBLチェッカー
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblChecker implements IDnsblChecker {

	public static final class ReadonlyDnsblChecker extends DnsblChecker {

		/**
		 * コンストラクター
		 */
		public ReadonlyDnsblChecker() {
		}

		/**
		 * コンストラクター
		 */
		public ReadonlyDnsblChecker(IDnsblChecker... checkers) {
			super(checkers);
		}

		/**
		 * コンストラクター
		 *
		 * @param chekcers
		 */
		public ReadonlyDnsblChecker(List<? extends IDnsblChecker> chekcers) {
			super(chekcers);
		}

		@Override
		public DnsblChecker addChecker(IDnsblChecker ...checkers) {
			throw new UnsupportedOperationException(getClass().getName() + " is readonly.");
		}

		@Override
		public DnsblChecker addCheckers(List<? extends IDnsblChecker> chekcers) {
			throw new UnsupportedOperationException(getClass().getName() + " is readonly.");
		}

		@Override
		public void clearCheckers() {
			throw new UnsupportedOperationException(getClass().getName() + " is readonly.");
		}

	}


	private static class Holder {
		static final DnsblChecker DEFAULT_INSTANCE = new ReadonlyDnsblChecker(DnsblService.Catalog.values());
	}

	/**
	 * @see DnsblService#values()
	 * @return
	 */
	public static DnsblChecker getDefaultInstance() {
		return Holder.DEFAULT_INSTANCE;
	}

	/**
	 * チェック実装リスト
	 */
	private final List<IDnsblChecker> checkers = new ArrayList<>();

	/**
	 * コンストラクター
	 */
	public DnsblChecker() {
	}

	/**
	 * コンストラクター
	 */
	public DnsblChecker(IDnsblChecker... checkers) {
		addChecker(checkers);
	}

	/**
	 * コンストラクター
	 *
	 * @param chekcers
	 */
	public DnsblChecker(List<? extends IDnsblChecker> chekcers) {
		addCheckers(chekcers);
	}

	/**
	 * スパムサーバー判定処理実装を追加します。
	 *
	 * @param service
	 * @return
	 */
	public DnsblChecker addChecker(IDnsblChecker... checkers) {
		for (IDnsblChecker checker : checkers) {
			this.checkers.add(checker);
		}
		return this;
	}

	/**
	 * スパムサーバー判定処理実装を追加します。
	 *
	 * @param service
	 * @return
	 */
	public DnsblChecker addCheckers(List<? extends IDnsblChecker> chekcers) {
		this.checkers.addAll(chekcers);
		return this;
	}

	public void clearCheckers() {
		checkers.clear();
	}

	private void requireCheckers() {
		if (checkers == null || checkers.isEmpty()) {
			throw new IllegalStateException("チェック処理が設定されていません。");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DnsblCheckResult checkIpAddress(String ipAddress) {
		requireCheckers();

		for (IDnsblChecker checker : checkers) {
			DnsblCheckResult result = checker.checkIpAddress(ipAddress);
			if (result.isListed()) {
				return result;
			}
		}

		return DnsblCheckResult.ok(ipAddress, "", this);
	}

	public DnsblCheckResult checkIpAddressAny(String ipAddress) {
		return checkIpAddress(ipAddress);
	}

	public List<DnsblCheckResult> checkIpAddressAll(String ipAddress) {
		requireCheckers();

		List<DnsblCheckResult> results = new ArrayList<DnsblCheckResult>();

		for (IDnsblChecker checker : checkers) {
			DnsblCheckResult result = checker.checkIpAddress(ipAddress);
			results.add(result);
		}

		return results;
	}

}
