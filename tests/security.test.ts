import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  isExampleComDemo,
  validateAuthorization,
  isPrivateOrBlockedIp,
  validateUrlSafety,
  parseAndNormalizeHostname,
} from '../src/security/url-validator.js';
import { isBlockedDomain } from '../src/security/blocklist.js';
import { secureLookupHook } from '../src/security/dns-guard.js';

describe('Security & SSRF Protections', () => {
  test('Authorization boundary requirements', () => {
    assert.equal(isExampleComDemo('https://example.com'), true);
    assert.equal(isExampleComDemo('http://www.example.com/path'), true);
    assert.equal(isExampleComDemo('https://attacker.com'), false);

    // Should pass for example.com without confirmAuthorizedUse
    assert.doesNotThrow(() => validateAuthorization('https://example.com', false));

    // Should throw for non-example domain without confirmAuthorizedUse
    assert.throws(() => validateAuthorization('https://customer-site.com', false), /Unauthorized: confirmAuthorizedUse=true is required/);

    // Should pass for non-example domain WITH confirmAuthorizedUse
    assert.doesNotThrow(() => validateAuthorization('https://customer-site.com', true));
  });

  test('Protocol, credential, and port restrictions', () => {
    assert.throws(() => validateUrlSafety('ftp://example.com'), /Prohibited protocol/);
    assert.throws(() => validateUrlSafety('file:///etc/passwd'), /Prohibited protocol/);
    assert.throws(() => validateUrlSafety('http://admin:secret@example.com'), /URL credentials are strictly prohibited/);
    assert.throws(() => validateUrlSafety('http://example.com:8080/path'), /Custom port '8080'/);
    assert.throws(() => validateUrlSafety('https://example.com:22/'), /Custom port '22'/);

    // Standard ports 80 and 443 are allowed
    assert.doesNotThrow(() => validateUrlSafety('http://example.com:80/'));
    assert.doesNotThrow(() => validateUrlSafety('https://example.com:443/'));
  });

  test('Enforced Domain Blocklist', () => {
    assert.equal(isBlockedDomain('169.254.169.254').blocked, true);
    assert.equal(isBlockedDomain('instance-data').blocked, true);
    assert.equal(isBlockedDomain('metadata.google.internal').blocked, true);
    assert.equal(isBlockedDomain('authorized-public-site.gov').blocked, false);
    assert.equal(isBlockedDomain('optout-example-domain.com').blocked, true);
    assert.equal(isBlockedDomain('example.com').blocked, false);

    assert.throws(() => validateUrlSafety('https://optout-example-domain.com'), /Blocked domain:/);
  });

  test('Private, Loopback, Link-Local, and Metadata IP Rejection across Formats', () => {
    const blockedHosts = [
      'localhost',
      'sub.localhost',
      '127.0.0.1',
      '127.0.1.1',
      '10.0.0.1',
      '172.16.0.1',
      '192.168.1.100',
      '169.254.169.254', // AWS/Cloud metadata
      '100.100.100.200', // Alibaba metadata
      '0.0.0.0',
      '224.0.0.1',
      '192.0.2.1', // Documentation
      '192.0.0.1', // IETF protocol assignments
      '198.18.0.1', // Benchmarking
      '198.19.255.254', // Benchmarking
      '::1',
      '::127.0.0.1', // Deprecated IPv4-compatible IPv6
      '::7f00:1', // Hex IPv4-compatible loopback
      'fe80::1',
      'fc00::1',
      '2001:db8::1',
      '2001:10::1', // ORCHID
      '2001:20::1', // ORCHIDv2
      '2002::1', // 6to4 tunneling
    ];

    for (const host of blockedHosts) {
      const res = isPrivateOrBlockedIp(host);
      assert.equal(res.blocked, true, `Expected ${host} to be blocked as private/prohibited IP.`);
      assert.throws(() => validateUrlSafety(`http://${host}/`), /SSRF security check failed|Blocked domain|Malformed URL/);
    }

    assert.equal(isPrivateOrBlockedIp('8.8.8.8').blocked, false);
    assert.equal(isPrivateOrBlockedIp('172.66.147.243').blocked, false);
  });

  test('Alternative IP Representations (Decimal, Hex, Octal, Encoded, IPv4-Mapped)', () => {
    const alternativeFormats = [
      { host: '2130706433', desc: 'Decimal for 127.0.0.1' },
      { host: '2852039166', desc: 'Decimal for 169.254.169.254' },
      { host: '0x7f000001', desc: 'Hex for 127.0.0.1' },
      { host: '0xa9fea9fe', desc: 'Hex for 169.254.169.254' },
      { host: '0177.0.0.1', desc: 'Octal for 127.0.0.1' },
      { host: '127.1', desc: 'Shortened dot-decimal for 127.0.0.1' },
      { host: '%31%32%37.%30.%30.%31', desc: 'URL-encoded 127.0.0.1' },
      { host: '::ffff:127.0.0.1', desc: 'IPv4-mapped IPv6 for 127.0.0.1' },
      { host: '0:0:0:0:0:ffff:7f00:1', desc: 'IPv4-mapped hex IPv6 for 127.0.0.1' },
    ];

    for (const item of alternativeFormats) {
      const normalized = parseAndNormalizeHostname(item.host);
      const res = isPrivateOrBlockedIp(normalized);
      assert.equal(res.blocked, true, `Expected ${item.desc} (${item.host}) to be blocked.`);
      assert.throws(() => validateUrlSafety(`http://${item.host}/`), /SSRF security check failed|Blocked domain|Malformed URL/);
    }
  });

  test('DNS Rebinding Socket Hook Interception', async () => {
    // Verify that secureLookupHook intercepts localhost resolution
    await new Promise<void>((resolve, reject) => {
      secureLookupHook('localhost', { all: true }, (err, records) => {
        if (err && err.code === 'ERR_SSRF_BLOCKED') {
          resolve();
        } else {
          reject(new Error(`Expected secureLookupHook to block localhost with ERR_SSRF_BLOCKED, got ${err?.message || JSON.stringify(records)}`));
        }
      });
    });
  });
});
