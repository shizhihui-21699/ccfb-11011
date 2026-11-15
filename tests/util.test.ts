import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  compareVersions,
  matchesHostPattern,
  matchesPathPrefix,
  normalizeHost,
  parseCookies,
  resolveRequestPath,
  safeEqual,
  sanitizeNextPath,
} from '../src/util.ts';

test('compareVersions handles uneven segment counts', () => {
  assert.equal(compareVersions('15.1.0', '14.0'), 1);
  assert.equal(compareVersions('10.0.19045', '10.0.19045'), 0);
  assert.equal(compareVersions('10.0.19044', '10.0.19045'), -1);
  assert.equal(compareVersions('12', '12.0.0'), 0);
  assert.equal(compareVersions('v2.3', '2.2.9'), 1);
  assert.equal(compareVersions('not-a-version', '1.0'), null);
});

test('host patterns match one label only', () => {
  assert.ok(matchesHostPattern('wiki.internal.example', '*.internal.example'));
  assert.ok(!matchesHostPattern('a.b.internal.example', '*.internal.example'));
  assert.ok(matchesHostPattern('WIKI.example.com', 'wiki.EXAMPLE.com'));
  assert.ok(!matchesHostPattern('evilwiki.example.com', 'wiki.example.com'));
  // Regex metacharacters in policy hosts are escaped.
  assert.ok(!matchesHostPattern('wikiXexample.com', 'wiki.example.com'));
});

test('normalizeHost strips port and trailing dot', () => {
  assert.equal(normalizeHost('Wiki.Example.COM:8443'), 'wiki.example.com');
  assert.equal(normalizeHost('example.com.'), 'example.com');
  assert.equal(normalizeHost('[::1]:8443'), '[::1]');
  assert.equal(normalizeHost(undefined), '');
});

test('path prefixes respect segment boundaries', () => {
  assert.ok(matchesPathPrefix('/wiki/page', '/wiki'));
  assert.ok(matchesPathPrefix('/wiki', '/wiki'));
  assert.ok(!matchesPathPrefix('/wikiLeak/page', '/wiki'));
  assert.ok(matchesPathPrefix('/anything', '/'));
  assert.ok(matchesPathPrefix('/wiki/page', '/wiki/'));
});

test('safeEqual is correct for equal and unequal inputs', () => {
  assert.ok(safeEqual('abc', 'abc'));
  assert.ok(!safeEqual('abc', 'abd'));
  assert.ok(!safeEqual('abc', 'abcd'));
});

test('cookie parsing tolerates malformed encoding', () => {
  assert.deepEqual(parseCookies('a=1; b=hello%20world'), { a: '1', b: 'hello world' });
  assert.deepEqual(parseCookies('bad=%E0%A4%A'), { bad: '%E0%A4%A' });
  assert.deepEqual(parseCookies(undefined), {});
});

test('login redirects cannot escape to another origin', () => {
  assert.equal(sanitizeNextPath('//evil.example'), '/');
  assert.equal(sanitizeNextPath('/wiki/page'), '/wiki/page');
  assert.equal(sanitizeNextPath('https://evil.example'), '/');
  assert.equal(sanitizeNextPath('/a\\b'), '/');
  assert.equal(sanitizeNextPath(null), '/');
});

test('request paths that could decode differently upstream are rejected', () => {
  assert.deepEqual(resolveRequestPath('/wiki/page'), { ok: true, path: '/wiki/page' });
  assert.equal(resolveRequestPath('/wiki/%2e%2e/finance').ok, false);
  assert.equal(resolveRequestPath('/wiki/%2E%2E%2Ffinance').ok, false);
  assert.equal(resolveRequestPath('/wiki%2fadmin').ok, false);
  assert.equal(resolveRequestPath('/wiki/%00').ok, false);
  assert.equal(resolveRequestPath('/wiki/%zz').ok, false);
  assert.equal(resolveRequestPath('/wiki/%0d%0aX-Injected:1').ok, false);
  assert.equal(resolveRequestPath('/wiki/a%20b').ok, true);
});

test('literal dot segments never reach policy matching', () => {
  // The URL parser collapses them before we see them; this is a backstop.
  assert.equal(resolveRequestPath('/wiki/../finance').ok, false);
  assert.equal(resolveRequestPath('/./wiki').ok, false);
});
