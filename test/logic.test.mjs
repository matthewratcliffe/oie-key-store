import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    ref, navLabel, parseStatus, parseConnection, parseBinding,
    typeLabel, since, problemText, authModeHint, encodeMap,
} from './logic.mjs';

test('ref builds a Velocity placeholder by concatenation', () => {
    assert.equal(ref('keystore', 'tok'), '${keystore.tok}');
    assert.equal(ref('', 'x'), '${.x}');
    assert.equal(ref('ns', ''), '${ns.}');
});

test('navLabel carries the fault count only when positive', () => {
    assert.equal(navLabel(null), 'Key Store');
    assert.equal(navLabel({ ok: false }), 'Key Store');
    assert.equal(navLabel({ faults: 3 }), 'Key Store (3)');
    assert.equal(navLabel({ faults: 0 }), 'Key Store');
    assert.equal(navLabel({ faults: 'x' }), 'Key Store'); // NaN -> 0
});

test('typeLabel maps known tokens and echoes unknown ones', () => {
    assert.equal(typeLabel('AWS_SECRETS_MANAGER'), 'AWS Secrets Manager');
    assert.equal(typeLabel('AZURE_KEY_VAULT'), 'Azure Key Vault');
    assert.equal(typeLabel('SOMETHING_ELSE'), 'SOMETHING_ELSE');
});

test('parseStatus splits a row with numeric coercion and defaults', () => {
    const s = parseStatus(['b1', 'apiTok', 'c1', 'Vault', 'OK', '', '1000', '2000', 'v3', '42', '${keystore.apiTok}'].join('\t'));
    assert.equal(s.variable, 'apiTok');
    assert.equal(s.state, 'OK');
    assert.equal(s.valueAt, 1000);
    assert.equal(s.length, 42);
    // Empty row -> all defaults, state OK, numbers 0.
    const e = parseStatus('');
    assert.equal(e.state, 'OK');
    assert.equal(e.valueAt, 0);
    assert.equal(e.length, 0);
});

test('parseConnection defaults enabled=true and reads hasCredential flag', () => {
    const c = parseConnection(['c1', 'Prod', 'AWS_SECRETS_MANAGER', 'STATIC_KEYS'].join('\t'));
    assert.equal(c.name, 'Prod');
    assert.equal(c.type, 'AWS_SECRETS_MANAGER');
    assert.equal(c.enabled, true);            // f[4] absent, !== 'false'
    assert.equal(c.hasCredential, false);     // f[17] absent
    const disabled = parseConnection(['c1', 'X', 'AZURE_KEY_VAULT', 'CLIENT_SECRET', 'false'].join('\t'));
    assert.equal(disabled.enabled, false);
    // type defaults to AZURE_KEY_VAULT on an empty row.
    assert.equal(parseConnection('').type, 'AZURE_KEY_VAULT');
});

test('parseBinding defaults enabled=true', () => {
    const b = parseBinding(['id1', 'tok', 'c1', 'Vault', 'secret/name'].join('\t'));
    assert.equal(b.variable, 'tok');
    assert.equal(b.secretId, 'secret/name');
    assert.equal(b.enabled, true);
    assert.equal(parseBinding(['id', 'v', 'c', 'l', 's', 'jf', 'ver', 'false'].join('\t')).enabled, false);
});

test('since is deterministic under an injected clock', () => {
    const now = 5_000_000_000_000;
    assert.equal(since(0, now), '');            // falsy guard, no "ago"
    assert.equal(since(now - 30_000, now), 'just now');  // < 90s
    assert.equal(since(now - 600_000, now), '10 min ago');
    assert.equal(since(now - 3 * 3_600_000, now), '3 h ago');
});

test('problemText merges error head and problem list', () => {
    assert.equal(problemText({ error: 'bad', problems: ['a', 'b'] }), 'bad\n• a\n• b');
    assert.equal(problemText({}), 'That could not be saved.');
    assert.equal(problemText({ problems: 'one' }), 'That could not be saved.\n• one');
});

test('authModeHint returns a hint for known modes, null otherwise', () => {
    assert.match(authModeHint('AWS', 'ENVIRONMENT'), /AWS_ACCESS_KEY_ID/);
    assert.equal(authModeHint('AWS', 'STATIC_KEYS'), null);
});

test('encodeMap escapes and drops null/undefined', () => {
    assert.equal(encodeMap({ a: null, b: 'v' }),
        '<map><entry><string>b</string><string>v</string></entry></map>');
    assert.match(encodeMap({ k: 'a&b<c' }), /a&amp;b&lt;c/);
});
