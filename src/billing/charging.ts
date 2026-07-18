import { Actor, log } from 'apify';
import type { PageAuditRecord } from '../types.js';

export const PAGE_AUDITED_EVENT = 'page-audited';

/** Returns the maximum number of paid page units that fit within the run budget. */
export function getPageAuditAllowance(requestedPages: number): number {
  try {
    const manager = Actor.getChargingManager();
    const pricing = manager.getPricingInfo();
    if (!pricing.isPayPerEvent || pricing.perEventPrices[PAGE_AUDITED_EVENT] === undefined) {
      return requestedPages;
    }
    return Math.min(requestedPages, manager.calculateMaxEventChargeCountWithinLimit(PAGE_AUDITED_EVENT));
  } catch (error) {
    log.warning(`Unable to determine the PPE page allowance: ${(error as Error).message}`);
    return 0;
  }
}

/**
 * Uses the Apify SDK's dataset push-with-charging transaction. The SDK limits
 * the pushed items before writing and charges only the items actually written.
 */
export async function atomicPushAndChargePage(
  record: PageAuditRecord,
): Promise<{ success: boolean; limitReached: boolean }> {
  const isBlocked = [0, 401, 403, 429, 451].includes(record.statusCode);

  try {
    if (isBlocked) {
      return { success: false, limitReached: false };
    }

    const manager = Actor.getChargingManager();
    const pricing = manager.getPricingInfo();
    const isPricedEvent = pricing.isPayPerEvent && pricing.perEventPrices[PAGE_AUDITED_EVENT] !== undefined;
    const result = await Actor.pushData(record, PAGE_AUDITED_EVENT);
    const success = !isPricedEvent || result.chargedCount === 1;
    const limitReached = isPricedEvent && (
      result.eventChargeLimitReached
      || result.chargeableWithinLimit[PAGE_AUDITED_EVENT] === 0
    );

    if (!success && limitReached) {
      log.warning(`Maximum cost reached before '${record.url}' could be stored and charged.`);
    }
    return { success, limitReached };
  } catch (error) {
    const message = (error as Error).message || String(error);
    const limitReached = /limit|maximum cost|maxTotalCharge/i.test(message);
    if (limitReached) {
      log.warning(`Maximum cost reached while storing '${record.url}': ${message}`);
    } else {
      log.error(`Failed to store and charge '${record.url}': ${message}`);
    }
    return { success: false, limitReached };
  }
}
