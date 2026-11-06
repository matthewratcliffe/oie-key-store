import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    ref, navLabel, parseStatus, parseConnection, parseBinding,
    typeLabel, since, problemText, authModeHint, encodeMap, directRef, parseDirect,
    suggestedPrefix, testerWarning,
} from './logic.mjs';

test('ref builds a Velocity placeholder by concatenation', () => {
    assert.equal(ref('keystore', 'tok'), '${keystore.tok}');
    assert.equal(ref('', 'x'), '${.x}');
    assert.equal(ref('ns', ''), '${ns.}');
});

test('directRef brackets the secret name and dots a plain field', () => {
    assert.equal(directRef('AWS', 'au-prod/htrak_postgres', 'password'),
        "${AWS['au-prod/htrak_postgres'].password}");
    // A field Velocity will not take after a dot goes in brackets too.
    assert.equal(directRef('AWS', 'x', 'db-host'), "${AWS['x']['db-host']}");
    assert.equal(directRef('AWS', 'plain/token'), "${AWS['plain/token']}");
    assert.equal(directRef('AWS', 'plain/token', ''), "${AWS['plain/token']}");
});

test('parseDirect splits a direct-reference status row', () => {
    const d = parseDirect(['AWS', 'au-prod/db', 'STALE', 'down', '1000', '2000', 'v1', '12',
        "${AWS['au-prod/db']}"].join('	'));
    assert.equal(d.prefix, 'AWS');
    assert.equal(d.secretId, 'au-prod/db');
    assert.equal(d.state, 'STALE');
    assert.equal(d.valueAt, 1000);
    assert.equal(d.length, 12);
    assert.equal(d.placeholder, "${AWS['au-prod/db']}");
    assert.equal(parseDirect('').state, 'OK');
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
    assert.equal(c.referencePrefix, '');      // f[19] absent: no direct references
    const f = Array(20).fill('');
    f[19] = 'AWS';
    assert.equal(parseConnection(f.join('	')).referencePrefix, 'AWS');
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

test('suggestedPrefix offers a name per provider, and nothing when it is taken', () => {
    assert.equal(suggestedPrefix('AWS_SECRETS_MANAGER', []), 'AWS');
    assert.equal(suggestedPrefix('AZURE_KEY_VAULT', ['keystore']), 'Azure');
    assert.equal(suggestedPrefix('ONEPASSWORD_CONNECT'), 'OnePassword');
    assert.equal(suggestedPrefix('BITWARDEN_SECRETS_MANAGER', []), 'Bitwarden');
    // Taken by another vault, or by the bindings' variable prefix: no suggestion,
    // since the server would refuse it.
    assert.equal(suggestedPrefix('AWS_SECRETS_MANAGER', ['AWS', 'keystore']), '');
    assert.equal(suggestedPrefix('AZURE_KEY_VAULT', ['Azure']), '');
    assert.equal(suggestedPrefix('NOT_A_PROVIDER', []), '');
});

test('every suggested prefix is a name the server accepts', () => {
    for (const type of ['AZURE_KEY_VAULT', 'AWS_SECRETS_MANAGER', 'ONEPASSWORD_CONNECT',
        'BITWARDEN_SECRETS_MANAGER']) {
        assert.match(suggestedPrefix(type, []), /^[A-Za-z][A-Za-z0-9_]*$/);
    }
});

test('testerWarning flags a readable secret that channels cannot reach', () => {
    const ok = { ok: true, masked: 'p**B', placeholder: '' };
    const noPrefix = { name: 'AWS', enabled: true, referencePrefix: '' };
    assert.match(testerWarning(noPrefix, ok), /"AWS" has no direct reference name/);
    const off = { name: 'AWS', enabled: false, referencePrefix: 'AWS' };
    assert.match(testerWarning(off, ok), /"AWS" is switched off/);
    // Switched off wins: setting a reference name would not help.
    assert.match(testerWarning({ name: 'v', enabled: false, referencePrefix: '' }, ok),
        /switched off/);
    // Falls back to the label when the vault has no name.
    assert.match(testerWarning({ label: 'eu vault', enabled: true }, ok), /"eu vault"/);
});

test('testerWarning is silent when the secret is usable or nothing was read', () => {
    const usable = { ok: true, placeholder: "${AWS['x'].apikey}" };
    assert.equal(testerWarning({ name: 'AWS', enabled: true, referencePrefix: 'AWS' },
        usable), null);
    assert.equal(testerWarning({ name: 'AWS', enabled: true, referencePrefix: 'AWS' },
        { ok: true, placeholder: '' }), null);
    assert.equal(testerWarning(null, { ok: true }), null);
    assert.equal(testerWarning({ name: 'AWS' }, null), null);
});
