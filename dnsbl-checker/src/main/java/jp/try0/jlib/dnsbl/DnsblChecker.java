package jp.try0.jlib.dnsbl;

import java.util.ArrayList;
import java.util.List;

/**
 * DNSBL cheker.
 *
 * @author Ryo Tsunoda
 *
 */
public class DnsblChecker implements IDnsblChecker {

	/**
	 * Readonly checker.
	 *
	 * @author Ryo Tsunoda
	 *
	 */
	public static final class ReadonlyDnsblChecker extends DnsblChecker {

		/**
		 * Constructor.
		 */
		public ReadonlyDnsblChecker() {
		}

		/**
		 * Constructor.
		 */
		public ReadonlyDnsblChecker(IDnsblChecker... checkers) {
			super(checkers);
		}

		/**
		 * Constructor.
		 *
		 * @param chekcers
		 */
		public ReadonlyDnsblChecker(List<? extends IDnsblChecker> chekcers) {
			super(chekcers);
		}

		@Override
		public DnsblChecker addCheckers(IDnsblChecker ...checkers) {
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
	 * the checkers.
	 */
	private final List<IDnsblChecker> checkers = new ArrayList<>();

	/**
	 * Constructor.
	 */
	public DnsblChecker() {
	}


	/**
	 * Constructor.
	 *
	 * @param checkers
	 */
	public DnsblChecker(IDnsblChecker... checkers) {
		addCheckers(checkers);
	}

	/**
	 * Constructor.
	 *
	 * @param chekcers
	 */
	public DnsblChecker(List<? extends IDnsblChecker> chekcers) {
		addCheckers(chekcers);
	}

	/**
	 * Adds dnsbl checkers.
	 *
	 * @param checkers
	 * @return
	 */
	public DnsblChecker addCheckers(IDnsblChecker... checkers) {
		for (IDnsblChecker checker : checkers) {
			this.checkers.add(checker);
		}
		return this;
	}

	/**
	 * Adds dnsbl checkers.
	 *
	 * @param chekcers
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
			throw new IllegalStateException("No checkers.");
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

	/**
	 * If detect that the IP is listed in Blacklist, return the result immediately.
	 *
	 * @param ipAddress
	 * @return
	 */
	public DnsblCheckResult checkAny(String ipAddress) {
		return checkIpAddress(ipAddress);
	}

	/**
	 * Check all dnsbl services.
	 *
	 * @param ipAddress
	 * @return
	 */
	public List<DnsblCheckResult> checkAll(String ipAddress) {
		requireCheckers();

		List<DnsblCheckResult> results = new ArrayList<DnsblCheckResult>();

		for (IDnsblChecker checker : checkers) {
			DnsblCheckResult result = checker.checkIpAddress(ipAddress);
			results.add(result);
		}

		return results;
	}

}
