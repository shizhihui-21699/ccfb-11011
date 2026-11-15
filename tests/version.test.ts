import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  compareVersions,
  meetsMinimumVersion,
  osFamily,
  parseVersion,
  resolveVersionFloor,
} from '../src/util/version.ts';

test('parses dotted versions, optional v prefix, ignores suffixes', () => {
  assert.deepEqual(parseVersion('15.2.0'), [15, 2, 0]);
  assert.deepEqual(parseVersion('v1.2'), [1, 2]);
  assert.deepEqual(parseVersion('6.8.0-45-generic'), [6, 8, 0]);
  assert.deepEqual(parseVersion('11.0.22631'), [11, 0, 22631]);
  assert.equal(parseVersion('not-a-version'), null);
  assert.equal(parseVersion(''), null);
});

test('compares numerically, not lexicographically', () => {
  assert.ok(compareVersions('9.0.0', '10.0.0') < 0);
  assert.ok(compareVersions('10.0.0', '9.0.0') > 0);
  assert.equal(compareVersions('14', '14.0.0'), 0);
  assert.equal(compareVersions('14.0.0', '14.0'), 0);
});

test('meetsMinimumVersion rejects unparseable actual values', () => {
  assert.equal(meetsMinimumVersion('15.2.0', '14.0.0'), true);
  assert.equal(meetsMinimumVersion('13.6.1', '14.0.0'), false);
  assert.equal(meetsMinimumVersion('unknown', '14.0.0'), false);
  assert.equal(meetsMinimumVersion('', '14.0.0'), false);
});

test('osFamily normalizes common spellings', () => {
  assert.equal(osFamily('macOS'), 'macos');
  assert.equal(osFamily('Mac OS X'), 'macos');
  assert.equal(osFamily('Darwin'), 'macos');
  assert.equal(osFamily('Windows'), 'windows');
  assert.equal(osFamily('Win32'), 'windows');
  assert.equal(osFamily('Ubuntu Linux'), 'linux');
  assert.equal(osFamily('Debian 12'), 'linux');
  assert.equal(osFamily('FreeBSD'), 'unknown');
});

test('resolveVersionFloor picks the matching family only', () => {
  const floor = { macos: '14.0.0', windows: '10.0.19045' };
  assert.equal(resolveVersionFloor(floor, 'macos'), '14.0.0');
  assert.equal(resolveVersionFloor(floor, 'windows'), '10.0.19045');
  assert.equal(resolveVersionFloor(floor, 'linux'), null);
  assert.equal(resolveVersionFloor('14.0.0', 'linux'), '14.0.0');
  assert.equal(resolveVersionFloor(undefined, 'macos'), null);
});

test('macOS and Windows build numbers are not cross-compared by accident', () => {
  // The bug this guards: a macOS floor of 14.0.0 applied to Windows 11 build
  // 22631 would pass, but applied to Windows 10 build 19045 would fail.
  assert.equal(meetsMinimumVersion('11.0.22631', '10.0.19045'), true);
  assert.equal(meetsMinimumVersion('10.0.17763', '10.0.19045'), false);
});
