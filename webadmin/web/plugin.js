/*
 * Key Store console UI.
 *
 * One surface: a "Key Store" page listing every secret binding with its current
 * state and the placeholder to paste into a connector field, plus the vault
 * connection editor. The nav item carries a count of bindings that are not
 * resolving, so a credential that stopped being readable is visible without
 * opening the page.
 *
 * Nothing on this page ever displays a secret value: the API does not return
 * one. What it shows is the name, where it comes from, whether the last read
 * worked and how long the value is -- which is enough to tell a truncated paste
 * from a working credential without putting the credential on a screen.
 *
 * Plain ES module JavaScript: no JSX, no imports, no build step. The console
 * dynamically import()s this file and passes its own `platform` into
 * register(), which is how the bundled plugins receive it. Importing
 * @oie/web-shell here would depend on the page's import map and risks a second
 * framework instance registering into a dead registry, which fails silently.
 */

const API = '/api/keystore';

/*
 * The engine serialises a Map through XStream, so "JSON" arrives shaped like
 * {"linked-hash-map":{"entry":[{"string":"ok","boolean":true}, ...]}} rather
 * than a plain object. Same reason the shell scripts in this repo parse XML.
 *
 * Entry shapes seen in practice:
 *   {"string":"ok","boolean":true}          key and value of different types
 *   {"string":["connectionId",null]}        both strings, so XStream collapses them
 *   {"string":"faults","int":0}
 */
function decode(node) {
    if (node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(decode);

    const keys = Object.keys(node);

    // A map: {"linked-hash-map": {...}} / {"map": {...}}
    const mapKey = keys.find(k => k === 'map' || k.endsWith('-map'));
    if (mapKey && keys.length === 1) {
        const inner = node[mapKey];
        if (inner === null) return {};
        let entries = inner.entry;
        if (entries == null) return {};
        if (!Array.isArray(entries)) entries = [entries];
        const out = {};
        for (const entry of entries) {
            const [k, v] = decodeEntry(entry);
            out[k] = v;
        }
        return out;
    }

    /*
     * A collection: {"list": {"string": [...]}} / {"list": null}.
     *
     * The name test is deliberately loose. An immutable list (List.of(), .toList())
     * serialises as java.util.ImmutableCollections$ListN wrapping a CollSer blob,
     * whose elements cannot be recovered at all -- the server side must never send
     * one. Recognising the shape anyway means the view gets an empty array instead
     * of an object, so a stray one degrades into "nothing to show" rather than
     * "(x || []).map is not a function".
     */
    const listKey = keys.find(k => k === 'list' || k === 'set'
        || /(^|[.$_-])(list|set|collection)/i.test(k));
    if (listKey && keys.length === 1) {
        const inner = node[listKey];
        if (inner === null) return [];
        const elemKey = Object.keys(inner).find(k => !k.startsWith('@'));
        if (elemKey === undefined) return [];
        const items = inner[elemKey];
        if (items !== null && typeof items === 'object' && !Array.isArray(items)) {
            return [];
        }
        return (Array.isArray(items) ? items : [items]).map(decode);
    }

    const SCALARS = new Set(['string', 'boolean', 'int', 'long', 'double', 'float',
        'short', 'byte', 'char', 'big-decimal', 'big-int']);
    if (keys.length === 1 && SCALARS.has(keys[0])) {
        const v = node[keys[0]];
        return Array.isArray(v) ? v.map(decode) : decode(v);
    }

    const out = {};
    for (const k of keys) out[k] = decode(node[k]);
    return out;
}

function decodeEntry(entry) {
    if (entry === null || typeof entry !== 'object') return [String(entry), null];
    const props = Object.keys(entry);

    // Collapsed form: one property whose value is [key, value].
    if (props.length === 1 && Array.isArray(entry[props[0]])) {
        const arr = entry[props[0]];
        return [String(arr[0]), arr.length > 1 ? decode(arr[1]) : null];
    }
    const keyVal = entry[props[0]];
    const key = Array.isArray(keyVal) ? String(keyVal[0]) : String(keyVal);
    if (props.length < 2) return [key, null];
    const valueName = props[1];
    return [key, decode({ [valueName]: entry[valueName] })];
}

/*
 * The mirror of decode(): a Map parameter has to arrive XStream-shaped, so a
 * plain JSON object body is rejected outright -- plain JSON gives a 500, the XML
 * map gives a 200. The engine's own scripts in this repo talk XML to the API for
 * the same reason.
 */
function encodeMap(obj) {
    const esc = v => String(v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    const entries = Object.keys(obj)
        // An undefined value means "not supplied", which is different from empty:
        // the server leaves a field alone when the key is absent. That is what
        // makes a blank credential field mean "keep the stored one".
        .filter(k => obj[k] !== undefined && obj[k] !== null)
        .map(k => `<entry><string>${esc(k)}</string><string>${esc(obj[k])}</string></entry>`)
        .join('');
    return `<map>${entries}</map>`;
}

const ICON_KEY = 'M21 2l-2 2m-7.6 7.6a5 5 0 11-7 7 5 5 0 017-7zm0 0L15 8m0 0l3 3 3-3-3-3';

/*
 * Nav items are read once when the shell mounts: registering one later does not
 * appear, and mutating a registered item's label does not re-render (both
 * verified against a running console). So the fault count has to be known
 * *before* register() runs, which is what this top-level await is for -- the
 * console awaits the module's import, so the fetch completes first.
 *
 * /summary is used rather than /status because it never contacts a vault: this
 * request is on the critical path for every page load, and it must not be the
 * reason the console feels slow.
 *
 * Kept on a short timeout and never allowed to reject: a plugin that fails to
 * load because a vault was slow would be a bad trade for a label.
 */
async function bootstrapSummary() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1500);
    try {
        const res = await fetch(`${API}/summary`, {
            headers: { Accept: 'application/json', 'X-Requested-With': 'oie-webadmin' },
            credentials: 'same-origin',
            signal: controller.signal,
        });
        if (!res.ok) return null;
        return decode(await res.json());
    } catch (err) {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

const BOOT = await bootstrapSummary();

/**
 * A placeholder as it is written in a connector field.
 *
 * Built by concatenation rather than written into a template literal. The two
 * notations collide: ${...} means substitution to JavaScript and means exactly
 * the same thing to Velocity, and every way of escaping one inside the other is
 * a trap for the next person to edit the line.
 */
function ref(namespace, name) {
    return '${' + namespace + '.' + name + '}';
}

function navLabel(boot) {
    if (!boot || boot.ok === false) return 'Key Store';
    const faults = Number(boot.faults) || 0;
    return faults > 0 ? `Key Store (${faults})` : 'Key Store';
}

/** How each binding state reads on screen, and how alarming it looks. */
const STATE_META = {
    OK: { label: 'OK', tone: 'ok' },
    STALE: { label: 'Stale', tone: 'warn' },
    FAILED: { label: 'Not available', tone: 'err' },
    UNAVAILABLE: { label: 'No vault', tone: 'err' },
    DISABLED: { label: 'Disabled', tone: 'dim' },
};

const TYPES = [
    { token: 'AZURE_KEY_VAULT', label: 'Azure Key Vault' },
    { token: 'AWS_SECRETS_MANAGER', label: 'AWS Secrets Manager' },
    { token: 'ONEPASSWORD_CONNECT', label: '1Password Connect' },
    { token: 'BITWARDEN_SECRETS_MANAGER', label: 'Bitwarden Secrets Manager' },
];

const AUTH_MODES = {
    AZURE_KEY_VAULT: [
        { token: 'CLIENT_SECRET', label: 'Client secret' },
        { token: 'MANAGED_IDENTITY', label: 'Managed identity' },
        { token: 'WORKLOAD_IDENTITY', label: 'Workload identity' },
    ],
    AWS_SECRETS_MANAGER: [
        { token: 'STATIC_KEYS', label: 'Access key' },
        { token: 'ENVIRONMENT', label: 'Environment variables' },
        { token: 'INSTANCE_ROLE', label: 'Instance or task role' },
        { token: 'WEB_IDENTITY', label: 'IAM role for service account' },
    ],
    ONEPASSWORD_CONNECT: [{ token: 'CONNECT_TOKEN', label: 'Connect token' }],
    BITWARDEN_SECRETS_MANAGER: [{ token: 'ACCESS_TOKEN', label: 'Access token' }],
};

/*
 * Which fields each provider's editor shows, and which of them is the
 * credential. Declarative because the four providers agree on almost nothing:
 * hand-writing four forms would mean four places to keep in step with the
 * server's field names, and the server is the one that decides them.
 *
 * `when` narrows a field to particular auth modes -- a tenant ID is meaningless
 * for a managed identity, and showing it implies it is needed.
 */
const FIELDS = {
    AZURE_KEY_VAULT: [
        { key: 'vaultUrl', label: 'Vault URL', placeholder: 'https://contoso.vault.azure.net',
          hint: 'The DNS name of the vault, from its overview page in the portal.' },
        { key: 'tenantId', label: 'Directory (tenant) ID', when: ['CLIENT_SECRET'] },
        { key: 'clientId', label: 'Application (client) ID',
          when: ['CLIENT_SECRET', 'MANAGED_IDENTITY', 'WORKLOAD_IDENTITY'],
          hint: 'For a managed identity, leave empty to use the system-assigned one.' },
        { key: 'clientSecret', label: 'Client secret', secret: true, when: ['CLIENT_SECRET'] },
        { key: 'apiVersion', label: 'API version', advanced: true,
          hint: 'Leave at 7.4 unless the vault is in a cloud that is behind.' },
    ],
    AWS_SECRETS_MANAGER: [
        { key: 'region', label: 'Region', placeholder: 'ap-southeast-2' },
        { key: 'accessKeyId', label: 'Access key ID', when: ['STATIC_KEYS'] },
        { key: 'secretAccessKey', label: 'Secret access key', secret: true,
          when: ['STATIC_KEYS'] },
        { key: 'roleArn', label: 'Assume role ARN', advanced: true,
          placeholder: 'arn:aws:iam::123456789012:role/oie-secrets',
          hint: 'Optional. Assumed after the credential above, for reading a secret '
              + 'owned by another account.' },
        { key: 'endpointOverride', label: 'Endpoint override', advanced: true,
          hint: 'Optional. For a VPC endpoint, GovCloud, or a local emulator.' },
    ],
    ONEPASSWORD_CONNECT: [
        { key: 'connectUrl', label: 'Connect server URL',
          placeholder: 'http://onepassword-connect:8080',
          hint: 'Your own Connect server, not 1Password.com.' },
        { key: 'connectToken', label: 'Connect token', secret: true,
          hint: 'The access token issued with the Connect credentials file. It only '
              + 'reaches the vaults it was granted.' },
    ],
    BITWARDEN_SECRETS_MANAGER: [
        { key: 'accessToken', label: 'Access token', secret: true,
          placeholder: '0.xxxxxxxx-....:....',
          hint: 'A machine account access token, complete with the part after the colon '
              + '-- that part is the key the values are decrypted with.' },
        { key: 'organizationId', label: 'Organisation ID', advanced: true,
          hint: 'Optional. Taken from the token when left empty.' },
        { key: 'identityUrl', label: 'Identity URL', advanced: true,
          hint: 'https://identity.bitwarden.eu for the EU cloud, or your own server.' },
        { key: 'apiUrl', label: 'API URL', advanced: true,
          hint: 'https://api.bitwarden.eu for the EU cloud, or your own server.' },
    ],
};

/** Which field holds the credential, so the editor can say "leave blank to keep". */
const CREDENTIAL_FIELD = {
    AZURE_KEY_VAULT: 'clientSecret',
    AWS_SECRETS_MANAGER: 'secretAccessKey',
    ONEPASSWORD_CONNECT: 'connectToken',
    BITWARDEN_SECRETS_MANAGER: 'accessToken',
};

/** How a secret is named, per provider. Said in the editor, not just the docs. */
const SECRET_ID_HINT = {
    AZURE_KEY_VAULT: 'The secret’s name in the vault, for example partner-api-token.',
    AWS_SECRETS_MANAGER: 'The secret’s name or full ARN, for example prod/hl7/partner-api.',
    ONEPASSWORD_CONNECT: 'Vault/Item, or Vault/Item/Field. Names or UUIDs both work, and an '
        + 'op://vault/item/field reference can be pasted as it stands.',
    BITWARDEN_SECRETS_MANAGER: 'The secret’s key, or its UUID.',
};

const VERSION_HINT = {
    AZURE_KEY_VAULT: 'Optional. A specific version id; empty means the current one.',
    AWS_SECRETS_MANAGER: 'Optional. A version id, or a stage such as AWSPREVIOUS; empty '
        + 'means AWSCURRENT.',
    ONEPASSWORD_CONNECT: 'Not supported by Connect. Leave empty.',
    BITWARDEN_SECRETS_MANAGER: 'Not supported by Secrets Manager. Leave empty.',
};

/** One tab-separated row from /status. See the note on KeyStoreService. */
function parseStatus(row) {
    const f = String(row).split('\t');
    return {
        bindingId: f[0] || '',
        variable: f[1] || '',
        connectionId: f[2] || '',
        connectionLabel: f[3] || '',
        state: f[4] || 'OK',
        detail: f[5] || '',
        valueAt: Number(f[6]) || 0,
        checkedAt: Number(f[7]) || 0,
        version: f[8] || '',
        length: Number(f[9]) || 0,
        placeholder: f[10] || '',
    };
}

/** One tab-separated row from /connections. */
function parseConnection(row) {
    const f = String(row).split('\t');
    return {
        id: f[0] || '',
        name: f[1] || '',
        type: f[2] || 'AZURE_KEY_VAULT',
        authMode: f[3] || '',
        enabled: f[4] !== 'false',
        vaultUrl: f[5] || '',
        tenantId: f[6] || '',
        clientId: f[7] || '',
        apiVersion: f[8] || '',
        region: f[9] || '',
        accessKeyId: f[10] || '',
        roleArn: f[11] || '',
        endpointOverride: f[12] || '',
        connectUrl: f[13] || '',
        identityUrl: f[14] || '',
        apiUrl: f[15] || '',
        organizationId: f[16] || '',
        hasCredential: f[17] === 'true',
        label: f[18] || '',
    };
}

/** One tab-separated row from /bindings. */
function parseBinding(row) {
    const f = String(row).split('\t');
    return {
        id: f[0] || '',
        variable: f[1] || '',
        connectionId: f[2] || '',
        connectionLabel: f[3] || '',
        secretId: f[4] || '',
        jsonField: f[5] || '',
        version: f[6] || '',
        enabled: f[7] !== 'false',
        description: f[8] || '',
        placeholder: f[9] || '',
    };
}

function typeLabel(token) {
    const found = TYPES.find(t => t.token === token);
    return found ? found.label : token;
}

/**
 * How long ago, as a phrase that already reads correctly on its own.
 *
 * Returns "just now" rather than a duration under a minute and a half, so
 * callers must not append "ago" themselves.
 */
function since(epochMs) {
    if (!epochMs) return '';
    const seconds = Math.max(0, Math.round((Date.now() - epochMs) / 1000));
    if (seconds < 90) return 'just now';
    const minutes = Math.round(seconds / 60);
    if (minutes < 90) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 36) return `${hours} h ago`;
    return `${Math.round(hours / 24)} d ago`;
}

export function register(platform) {
    const React = platform.React;
    const h = React.createElement;

    // ------------------------------------------------------------------
    // API helper
    // ------------------------------------------------------------------
    async function call(method, path, body) {
        const headers = {
            Accept: 'application/json',
            'X-Requested-With': 'oie-webadmin',
        };
        if (body !== undefined) {
            headers['Content-Type'] = 'application/xml';
        }
        const res = await fetch(API + path, {
            method,
            headers,
            credentials: 'same-origin',
            body: body === undefined ? undefined : encodeMap(body),
        });

        let payload = null;
        const text = await res.text();
        if (text) {
            try {
                payload = decode(JSON.parse(text));
            } catch (err) {
                payload = { error: text };
            }
        }
        if (!res.ok) {
            const error = new Error(
                (payload && (payload.error || payload.message)) || `HTTP ${res.status}`);
            error.status = res.status;
            error.payload = payload;
            throw error;
        }
        return payload || {};
    }

    /** Turns a rejected save into one readable string, problems included. */
    function problemText(result) {
        const problems = result && result.problems;
        const list = Array.isArray(problems) ? problems : (problems ? [problems] : []);
        const head = (result && result.error) || 'That could not be saved.';
        return list.length ? `${head}\n• ${list.join('\n• ')}` : head;
    }

    // ------------------------------------------------------------------
    // Presentation helpers
    // ------------------------------------------------------------------

    /*
     * The shell's .view class is a flex column with overflow-y: hidden, so child
     * sections flex-shrink to fit the viewport instead of overflowing -- scrollHeight
     * ends up equal to clientHeight and there is nothing to scroll, which bites as
     * soon as an editor is open.
     *
     * .view is our own element here, so an inline display/overflow wins over the
     * class. block rather than flex means the sections keep their natural height and
     * the container scrolls.
     */
    const viewStyle = extra => Object.assign({
        display: 'block',
        overflowY: 'auto',
        height: '100%',
        boxSizing: 'border-box',
        padding: '1rem',
    }, extra || {});

    /*
     * Everything below renders with the shell's own classes -- .panel,
     * .panel-header, .panel-body, .field, .hint, .btn, .tag, .mono, .form-grid --
     * rather than inline styling. They carry the app's spacing, borders, radii and
     * both themes, so this view matches the rest of the console and follows it when
     * the theme changes. Inline style is used only for what those classes do not
     * cover, and then in terms of the app's CSS variables.
     */
    function Panel(title, children, opts) {
        const o = opts || {};
        return h('div', {
            key: o.key,
            className: 'panel',
            style: { marginBottom: '11px' },
        }, [
            title ? h('div', { key: 'h', className: 'panel-header' }, [
                h('span', { key: 't' }, title),
                o.badge || null,
            ]) : null,
            h('div', { key: 'b', className: 'panel-body' }, children),
        ]);
    }

    /**
     * One labelled control in a .form-grid.
     *
     * `opts.key` matters wherever the set of fields is built from data rather
     * than written out: the vault editor rebuilds its field list when the auth
     * mode changes, and without keys React reconciles by position, which carries
     * the text of one input into the one that replaced it.
     */
    function Field(label, control, hint, opts) {
        const o = opts || {};
        return h('div', {
            key: o.key,
            className: 'field',
            style: o.span ? { gridColumn: '1 / -1' } : undefined,
        }, [
            h('label', { key: 'l' }, label),
            control,
            hint ? h('div', { key: 'h', className: 'hint' }, hint) : null,
        ]);
    }

    function Button(label, onClick, opts) {
        const o = opts || {};
        const classes = ['btn'];
        if (o.primary) classes.push('btn-primary');
        if (o.danger) classes.push('btn-danger');
        return h('button', {
            type: 'button',
            className: classes.join(' '),
            disabled: !!o.disabled,
            title: o.title || '',
            onClick,
            style: { marginRight: '6px' },
        }, label);
    }

    function Banner(kind, children, key) {
        const token = { error: '--err', warn: '--warn', ok: '--ok', info: '--accent' }[kind]
            || '--accent';
        return h('div', {
            key,
            className: 'hint',
            style: {
                background: `color-mix(in srgb, var(${token}) 14%, var(--bg1))`,
                border: `1px solid color-mix(in srgb, var(${token}) 55%, transparent)`,
                borderRadius: 'var(--radius)',
                color: 'var(--text)',
                fontSize: '11px',
                padding: '7px 11px',
                marginBottom: '9px',
                whiteSpace: 'pre-wrap',
            },
        }, children);
    }

    /** A state chip. Colour carries the same information as the words, not instead. */
    function StateChip(state) {
        const meta = STATE_META[state] || { label: state, tone: 'dim' };
        const token = { ok: '--ok', err: '--err', warn: '--warn', dim: '--text-faint' }[meta.tone];
        return h('span', {
            className: 'tag',
            style: {
                background: `color-mix(in srgb, var(${token}) 18%, transparent)`,
                borderColor: `color-mix(in srgb, var(${token}) 55%, transparent)`,
                color: meta.tone === 'dim' ? 'var(--text-dim)' : `var(${token})`,
                whiteSpace: 'nowrap',
            },
            title: state,
        }, meta.label);
    }

    /**
     * The placeholder, as something that can be copied.
     *
     * A button rather than selectable text: this string is retyped into a
     * connector field every time a binding is used, and a typo in it fails at
     * runtime as a literal ${...} reaching a remote system as a password.
     *
     * A real component, rendered with h(Placeholder, ...), because it holds
     * state. Calling it as a plain function would run its hook inside whichever
     * component rendered the row, and the number of rows changes -- which is
     * exactly the "rendered more hooks than during the previous render" fault.
     */
    function Placeholder(props) {
        const text = props.text;
        const [copied, setCopied] = React.useState(false);
        return h('button', {
            type: 'button',
            className: 'tag mono',
            title: 'Copy ' + text,
            style: { cursor: 'pointer', whiteSpace: 'nowrap' },
            onClick: async () => {
                try {
                    await navigator.clipboard.writeText(text);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1200);
                } catch (err) {
                    // Clipboard access is refused outside a secure context, which
                    // an engine reached over plain http is. The text is on screen
                    // either way, so this is a convenience that is allowed to fail.
                    setCopied(false);
                }
            },
        }, copied ? 'copied' : text);
    }

    function Select(value, options, onChange, opts) {
        const o = opts || {};
        return h('select', {
            value: value || '',
            disabled: !!o.disabled,
            onChange: e => onChange(e.target.value),
        }, options.map(option => h('option', {
            key: option.token,
            value: option.token,
        }, option.label)));
    }

    function Text(value, onChange, opts) {
        const o = opts || {};
        return h('input', {
            type: o.secret ? 'password' : 'text',
            value: value || '',
            placeholder: o.placeholder || '',
            autoComplete: o.secret ? 'new-password' : 'off',
            spellCheck: false,
            disabled: !!o.disabled,
            onChange: e => onChange(e.target.value),
        });
    }

    function Check(checked, label, onChange) {
        return h('label', {
            style: { display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 'normal' },
        }, [
            h('input', {
                key: 'i',
                type: 'checkbox',
                checked: !!checked,
                onChange: e => onChange(e.target.checked),
            }),
            h('span', { key: 's' }, label),
        ]);
    }

    // ------------------------------------------------------------------
    // The Key Store page
    // ------------------------------------------------------------------
    function KeyStoreView() {
        const [status, setStatus] = React.useState(null);
        const [connections, setConnections] = React.useState([]);
        const [bindings, setBindings] = React.useState([]);
        const [busy, setBusy] = React.useState('');
        const [error, setError] = React.useState(null);
        const [notice, setNotice] = React.useState(null);
        const [editingBinding, setEditingBinding] = React.useState(null);
        const [editingConnection, setEditingConnection] = React.useState(null);
        const [showSettings, setShowSettings] = React.useState(false);
        const [confirmDelete, setConfirmDelete] = React.useState(null);

        const load = React.useCallback(async (opts) => {
            const o = opts || {};
            setBusy(o.label || 'Loading');
            setError(null);
            try {
                const s = await call('GET', `/status?refresh=${o.refresh ? 'true' : 'false'}`);
                setStatus(s);
                const c = await call('GET', '/connections');
                setConnections((c.connections || []).map(parseConnection));
                const b = await call('GET', '/bindings');
                setBindings((b.bindings || []).map(parseBinding));
            } catch (err) {
                setError(err.message);
            } finally {
                setBusy('');
            }
        }, []);

        React.useEffect(() => { load(); }, [load]);

        const run = async (label, fn) => {
            setBusy(label);
            setError(null);
            setNotice(null);
            try {
                await fn();
            } catch (err) {
                setError(err.message);
            } finally {
                setBusy('');
            }
        };

        const namespace = (status && status.namespace) || 'keystore';
        const statuses = ((status && status.results) || []).map(parseStatus);
        const statusFor = id => statuses.find(s => s.bindingId === id);
        const connectionFor = id => connections.find(c => c.id === id);

        return h('div', { className: 'view', style: viewStyle() }, [
            error ? Banner('error', error, 'error') : null,
            notice ? Banner('ok', notice, 'notice') : null,

            SecretsPanel(),
            VaultsPanel(),
            showSettings ? SettingsPanel() : null,
        ]);

        // --------------------------------------------------------------
        function SecretsPanel() {
            const faults = statuses.filter(s =>
                s.state === 'FAILED' || s.state === 'STALE' || s.state === 'UNAVAILABLE');

            return Panel('Secrets', [
                h('div', { key: 'bar', style: { marginBottom: '9px' } }, [
                    Button('Add a secret', () => setEditingBinding({
                        connectionId: connections.length === 1 ? connections[0].id : '',
                        enabled: true,
                    }), { primary: true, disabled: !!busy || connections.length === 0,
                        title: connections.length === 0
                            ? 'Add a vault first' : '' }),
                    Button('Read them now', () => run('Reading',
                        () => load({ refresh: true, label: 'Reading' })),
                        { disabled: !!busy }),
                    Button(showSettings ? 'Hide settings' : 'Settings',
                        () => setShowSettings(!showSettings), { disabled: !!busy }),
                    busy ? h('span', { key: 'b', className: 'hint',
                        style: { marginLeft: '6px' } }, busy + '…') : null,
                ]),

                status && status.lastPassAt
                    ? h('div', { key: 'when', className: 'hint',
                        style: { marginBottom: '9px' } },
                        `Last read ${since(status.lastPassAt)}, every `
                        + `${Math.round((status.refreshIntervalSeconds || 900) / 60)} min. `
                        + (status.serveStaleOnFailure
                            ? 'A value that cannot be re-read keeps its last known good value.'
                            : 'A value that cannot be re-read stops being published.'))
                    : null,

                faults.length
                    ? Banner('error', faults.length === 1
                        ? 'One secret is not resolving: ' + ref(namespace, faults[0].variable) + '.'
                        : `${faults.length} secrets are not resolving.`, 'faults')
                    : null,

                connections.length === 0
                    ? h('div', { key: 'empty', className: 'hint' },
                        'Add a vault below, then bind the secrets you want channels to use.')
                    : bindings.length === 0
                        ? h('div', { key: 'empty', className: 'hint' },
                            'No secrets are bound yet. A binding gives a secret a name, and '
                            + 'channels use that name as ' + ref(namespace, 'name') + ' in any '
                            + 'connector field.')
                        : BindingTable(),

                editingBinding
                    ? h(BindingEditor, {
                        key: 'binding-editor',
                        initial: editingBinding,
                        connections,
                        namespace,
                        onCancel: () => setEditingBinding(null),
                        onSaved: async (message) => {
                            setEditingBinding(null);
                            setNotice(message);
                            await load();
                        },
                    })
                    : null,
            ], { badge: faults.length
                ? h('span', { className: 'tag', style: {
                    background: 'color-mix(in srgb, var(--err) 18%, transparent)',
                    borderColor: 'color-mix(in srgb, var(--err) 55%, transparent)',
                    color: 'var(--err)',
                } }, `${faults.length} not resolving`)
                : null });
        }

        function BindingTable() {
            return h('table', { key: 'table', className: 'table' }, [
                h('thead', { key: 'h' }, h('tr', {}, [
                    h('th', { key: 'a' }, 'Use in a channel as'),
                    h('th', { key: 'b' }, 'From'),
                    h('th', { key: 'c' }, 'Secret'),
                    h('th', { key: 'd' }, 'State'),
                    h('th', { key: 'e' }, ''),
                ])),
                h('tbody', { key: 'b' }, bindings.map(binding => {
                    const state = statusFor(binding.id);
                    const connection = connectionFor(binding.connectionId);
                    return h('tr', { key: binding.id }, [
                        h('td', { key: 'a' }, [
                            h(Placeholder, { key: 'p', text: binding.placeholder }),
                            binding.description
                                ? h('div', { key: 'd', className: 'hint' }, binding.description)
                                : null,
                        ]),
                        h('td', { key: 'b' }, [
                            h('div', { key: 'n' }, binding.connectionLabel || '(missing)'),
                            connection
                                ? h('div', { key: 't', className: 'hint' },
                                    typeLabel(connection.type))
                                : null,
                        ]),
                        h('td', { key: 'c' }, [
                            h('span', { key: 's', className: 'mono' }, binding.secretId),
                            binding.jsonField
                                ? h('div', { key: 'f', className: 'hint' },
                                    'field: ' + binding.jsonField)
                                : null,
                            binding.version
                                ? h('div', { key: 'v', className: 'hint' },
                                    'version: ' + binding.version)
                                : null,
                        ]),
                        h('td', { key: 'd' }, [
                            StateChip(state ? state.state
                                : (binding.enabled ? 'FAILED' : 'DISABLED')),
                            state && state.detail
                                ? h('div', { key: 'x', className: 'hint' }, state.detail)
                                : null,
                            state && state.state === 'OK'
                                ? h('div', { key: 'y', className: 'hint' },
                                    `${state.length} characters, read ${since(state.valueAt)}`)
                                : null,
                        ]),
                        h('td', { key: 'e', style: { whiteSpace: 'nowrap' } }, [
                            Button('Edit', () => setEditingBinding(binding),
                                { disabled: !!busy }),
                            Button('Delete', () => setConfirmDelete({
                                kind: 'binding', id: binding.id, name: binding.variable,
                            }), { danger: true, disabled: !!busy }),
                        ]),
                    ]);
                })),
            ]);
        }

        // --------------------------------------------------------------
        function VaultsPanel() {
            return Panel('Vaults', [
                h('div', { key: 'bar', style: { marginBottom: '9px' } }, [
                    Button('Add a vault', () => setEditingConnection({
                        type: 'AZURE_KEY_VAULT', authMode: 'CLIENT_SECRET', enabled: true,
                    }), { disabled: !!busy }),
                ]),

                connections.length === 0
                    ? h('div', { key: 'empty', className: 'hint' },
                        'No vaults are configured.')
                    : h('table', { key: 'table', className: 'table' }, [
                        h('thead', { key: 'h' }, h('tr', {}, [
                            h('th', { key: 'a' }, 'Name'),
                            h('th', { key: 'b' }, 'Provider'),
                            h('th', { key: 'c' }, 'Signs in with'),
                            h('th', { key: 'd' }, 'Used by'),
                            h('th', { key: 'e' }, ''),
                        ])),
                        h('tbody', { key: 'b' }, connections.map(connection => {
                            const used = bindings.filter(
                                b => b.connectionId === connection.id).length;
                            const modes = AUTH_MODES[connection.type] || [];
                            const mode = modes.find(m => m.token === connection.authMode);
                            return h('tr', { key: connection.id }, [
                                h('td', { key: 'a' }, [
                                    h('div', { key: 'n' }, connection.name || connection.label),
                                    connection.enabled ? null
                                        : h('div', { key: 'd', className: 'hint' },
                                            'Switched off'),
                                ]),
                                h('td', { key: 'b' }, typeLabel(connection.type)),
                                h('td', { key: 'c' }, [
                                    h('div', { key: 'm' }, mode ? mode.label : connection.authMode),
                                    connection.hasCredential
                                        ? h('div', { key: 'c', className: 'hint' },
                                            'A credential is stored')
                                        : null,
                                ]),
                                h('td', { key: 'd' },
                                    used === 1 ? '1 secret' : `${used} secrets`),
                                h('td', { key: 'e', style: { whiteSpace: 'nowrap' } }, [
                                    Button('Edit', () => setEditingConnection(connection),
                                        { disabled: !!busy }),
                                    Button('Delete', () => setConfirmDelete({
                                        kind: 'connection', id: connection.id,
                                        name: connection.name || connection.label,
                                        used,
                                    }), { danger: true, disabled: !!busy }),
                                ]),
                            ]);
                        })),
                    ]),

                editingConnection
                    ? h(ConnectionEditor, {
                        key: 'vault-editor',
                        initial: editingConnection,
                        onCancel: () => setEditingConnection(null),
                        onSaved: async (message) => {
                            setEditingConnection(null);
                            setNotice(message);
                            await load();
                        },
                    })
                    : null,

                confirmDelete ? DeleteConfirm() : null,
            ], { key: 'vaults' });
        }

        function DeleteConfirm() {
            const d = confirmDelete;
            const warning = d.kind === 'connection' && d.used > 0
                ? ` ${d.used} secret binding(s) use it and will stop resolving.`
                : '';
            return h('div', { key: 'confirm', style: { marginTop: '9px' } }, [
                Banner('warn', `Delete "${d.name}"?${warning}`, 'confirm'),
                Button('Delete', () => run('Deleting', async () => {
                    const path = d.kind === 'connection'
                        ? `/connections/_delete?id=${encodeURIComponent(d.id)}`
                        : `/bindings/_delete?id=${encodeURIComponent(d.id)}`;
                    const result = await call('POST', path, {});
                    setConfirmDelete(null);
                    setNotice(result.warning || `"${d.name}" was deleted.`);
                    await load();
                }), { danger: true, disabled: !!busy }),
                Button('Keep it', () => setConfirmDelete(null), { disabled: !!busy }),
            ]);
        }

        // --------------------------------------------------------------
        function SettingsPanel() {
            return h(SettingsForm, {
                key: 'settings',
                status,
                onSaved: async (messages) => {
                    setNotice(messages.join(' '));
                    await load();
                },
                onError: setError,
            });
        }
    }

    // ------------------------------------------------------------------
    // The binding editor
    // ------------------------------------------------------------------
    function BindingEditor(props) {
        const initial = props.initial;
        const connections = props.connections;
        const namespace = props.namespace;
        const [variable, setVariable] = React.useState(initial.variable || '');
        const [connectionId, setConnectionId] = React.useState(initial.connectionId || '');
        const [secretId, setSecretId] = React.useState(initial.secretId || '');
        const [jsonField, setJsonField] = React.useState(initial.jsonField || '');
        const [version, setVersion] = React.useState(initial.version || '');
        const [description, setDescription] = React.useState(initial.description || '');
        const [enabled, setEnabled] = React.useState(initial.enabled !== false);
        const [busy, setBusy] = React.useState(false);
        const [error, setError] = React.useState(null);

        const connection = connections.find(c => c.id === connectionId);
        const type = connection ? connection.type : 'AZURE_KEY_VAULT';
        const versionSupported = type === 'AZURE_KEY_VAULT' || type === 'AWS_SECRETS_MANAGER';

        const save = async () => {
            setBusy(true);
            setError(null);
            try {
                const result = await call('POST', '/bindings', {
                    id: initial.id,
                    variable,
                    connectionId,
                    secretId,
                    jsonField,
                    version,
                    description,
                    enabled: String(enabled),
                });
                if (result.ok === false) {
                    setError(problemText(result));
                    return;
                }
                props.onSaved(ref(namespace, variable) + ' was saved.');
            } catch (err) {
                setError(err.message);
            } finally {
                setBusy(false);
            }
        };

        return h('div', { key: 'editor', style: { marginTop: '11px' } }, Panel(
            initial.id ? 'Edit secret' : 'Add a secret', [
                error ? Banner('error', error, 'error') : null,
                h('div', { key: 'grid', className: 'form-grid' }, [
                    Field('Name channels will use',
                        Text(variable, setVariable, { placeholder: 'partnerApiToken' }),
                        variable
                            ? 'Written ' + ref(namespace, variable) + ' in a connector field, '
                              + `or KeyStore.get('${variable}') in a script.`
                            : 'Letters, digits and underscores, starting with a letter.'),
                    Field('Vault',
                        Select(connectionId, connections.map(c => ({
                            token: c.id, label: (c.name || c.label) + ' — '
                                + typeLabel(c.type),
                        })), setConnectionId),
                        connection && !connection.enabled
                            ? 'This vault is switched off, so the secret will not be read.'
                            : null),
                    Field('Secret', Text(secretId, setSecretId),
                        SECRET_ID_HINT[type], { span: true }),
                    Field('Field within the secret',
                        Text(jsonField, setJsonField, { placeholder: 'password' }),
                        'Optional. For a secret that holds a JSON object, the field to '
                        + 'take out of it. Empty means the whole value.'),
                    Field('Version',
                        Text(version, setVersion, { disabled: !versionSupported }),
                        VERSION_HINT[type]),
                    Field('Note', Text(description, setDescription),
                        'Optional. What this is for, for whoever reads the list later.',
                        { span: true }),
                    Field('Enabled', Check(enabled, 'Read this secret', setEnabled),
                        'Switch off to stop publishing it without deleting the binding.'),
                ]),
                h('div', { key: 'buttons', style: { marginTop: '9px' } }, [
                    Button('Save', save, { primary: true, disabled: busy }),
                    Button('Cancel', props.onCancel, { disabled: busy }),
                ]),
            ]));
    }

    // ------------------------------------------------------------------
    // The vault editor
    // ------------------------------------------------------------------
    function ConnectionEditor(props) {
        const initial = props.initial;
        const [values, setValues] = React.useState(() => Object.assign({
            name: '', type: 'AZURE_KEY_VAULT', authMode: 'CLIENT_SECRET', enabled: true,
        }, initial));
        const [secrets, setSecrets] = React.useState({});
        const [showAdvanced, setShowAdvanced] = React.useState(false);
        const [busy, setBusy] = React.useState('');
        const [error, setError] = React.useState(null);
        const [notes, setNotes] = React.useState(null);

        const type = values.type;
        const modes = AUTH_MODES[type] || [];
        const credentialField = CREDENTIAL_FIELD[type];

        const set = (key, value) => setValues(v => Object.assign({}, v, { [key]: value }));

        /*
         * Changing the provider resets the auth mode, because the modes do not
         * overlap: keeping "Access key" selected after switching to Key Vault
         * would submit a mode the server rejects, and the message it gives back
         * would be about the mode rather than about the change that caused it.
         */
        const setType = next => setValues(v => Object.assign({}, v, {
            type: next,
            authMode: (AUTH_MODES[next] || [{}])[0].token,
        }));

        const visibleFields = (FIELDS[type] || []).filter(field => {
            if (field.when && !field.when.includes(values.authMode)) return false;
            if (field.advanced && !showAdvanced) return false;
            return true;
        });

        /** The form as the server wants it. Credentials only when actually typed. */
        const payload = () => {
            const body = {
                id: initial.id,
                name: values.name,
                type: values.type,
                authMode: values.authMode,
                enabled: String(values.enabled !== false),
            };
            for (const field of (FIELDS[type] || [])) {
                if (field.secret) {
                    // Sent only when something was typed. An empty one means
                    // "keep what is stored", which is the only way the editor can
                    // work at all given the API never returns a credential.
                    if (secrets[field.key]) body[field.key] = secrets[field.key];
                } else if (values[field.key] !== undefined) {
                    body[field.key] = values[field.key];
                }
            }
            return body;
        };

        const test = async () => {
            setBusy('Testing');
            setError(null);
            setNotes(null);
            try {
                const result = await call('POST', '/connections/_test', payload());
                if (result.ok === false) {
                    setError(problemText(result));
                    return;
                }
                const lines = Array.isArray(result.notes) ? result.notes
                    : (result.notes ? [result.notes] : ['It works.']);
                setNotes(lines);
            } catch (err) {
                setError(err.message);
            } finally {
                setBusy('');
            }
        };

        const save = async () => {
            setBusy('Saving');
            setError(null);
            try {
                const result = await call('POST', '/connections', payload());
                if (result.ok === false) {
                    setError(problemText(result));
                    return;
                }
                props.onSaved(`"${values.name}" was saved.`);
            } catch (err) {
                setError(err.message);
            } finally {
                setBusy('');
            }
        };

        return h('div', { key: 'editor', style: { marginTop: '11px' } }, Panel(
            initial.id ? 'Edit vault' : 'Add a vault', [
                error ? Banner('error', error, 'error') : null,
                notes ? Banner('ok', notes.join('\n'), 'notes') : null,

                h('div', { key: 'grid', className: 'form-grid' }, [
                    Field('Name', Text(values.name, v => set('name', v),
                        { placeholder: 'Production Key Vault' }),
                        'What this vault is called in the secret list.'),
                    Field('Provider', Select(type, TYPES, setType)),
                    modes.length > 1
                        ? Field('Sign in with',
                            Select(values.authMode, modes, v => set('authMode', v)),
                            authModeHint(type, values.authMode))
                        : null,

                    ...visibleFields.map(field => Field(
                        field.label,
                        field.secret
                            ? Text(secrets[field.key] || '',
                                v => setSecrets(s => Object.assign({}, s, { [field.key]: v })),
                                { secret: true,
                                  placeholder: initial.hasCredential
                                    ? 'Leave blank to keep the stored one'
                                    : (field.placeholder || '') })
                            : Text(values[field.key], v => set(field.key, v),
                                { placeholder: field.placeholder || '' }),
                        field.hint,
                        { key: field.key,
                          span: !!field.secret || field.key === 'vaultUrl'
                            || field.key === 'connectUrl' })),

                    Field('Enabled', Check(values.enabled !== false, 'Read from this vault',
                        v => set('enabled', v)),
                        'Switch off to stop reading from it without deleting it.'),
                ]),

                h('div', { key: 'buttons', style: { marginTop: '9px' } }, [
                    Button('Save', save, { primary: true, disabled: !!busy }),
                    Button('Test', test, { disabled: !!busy,
                        title: 'Authenticate and report what this identity can see' }),
                    Button(showAdvanced ? 'Fewer options' : 'More options',
                        () => setShowAdvanced(!showAdvanced), { disabled: !!busy }),
                    Button('Cancel', props.onCancel, { disabled: !!busy }),
                    busy ? h('span', { key: 'b', className: 'hint',
                        style: { marginLeft: '6px' } }, busy + '…') : null,
                ]),
            ]));
    }

    /** What each auth mode needs of the environment, said before it is chosen. */
    function authModeHint(type, mode) {
        const hints = {
            MANAGED_IDENTITY: 'Needs this engine to be running on Azure with an identity '
                + 'assigned. Nothing is stored here.',
            WORKLOAD_IDENTITY: 'Needs the pod to have AZURE_FEDERATED_TOKEN_FILE set by the '
                + 'AKS workload identity webhook. Nothing is stored here.',
            ENVIRONMENT: 'Reads AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from the '
                + 'engine’s environment.',
            INSTANCE_ROLE: 'Uses the ECS task role, or the EC2 instance role over IMDSv2. '
                + 'Nothing is stored here.',
            WEB_IDENTITY: 'Needs AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN, which EKS '
                + 'sets for a service account with a role annotation.',
        };
        return hints[mode] || null;
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------
    function SettingsForm(props) {
        const status = props.status;
        const [namespace, setNamespace] = React.useState(
            (status && status.namespace) || 'keystore');
        // Not named setInterval: that shadows the global of the same name for the
        // whole component, and the next person to reach for a timer in here would
        // get a state setter instead with no error to say so.
        const [refreshSeconds, setRefreshSeconds] = React.useState(
            (status && status.refreshIntervalSeconds) || 900);
        const [stale, setStale] = React.useState(
            !status || status.serveStaleOnFailure !== false);
        const [events, setEvents] = React.useState(
            !status || status.writeServerEvents !== false);
        const [busy, setBusy] = React.useState(false);

        return Panel('Settings', [
            h('div', { key: 'grid', className: 'form-grid' }, [
                Field('Variable prefix', Text(namespace, setNamespace),
                    'Secrets are published as ' + ref(namespace || 'keystore', 'name') + '. '
                    + 'Changing it means editing every connector field that uses one.'),
                Field('Read every',
                    h('input', {
                        type: 'number',
                        min: 60,
                        step: 60,
                        value: refreshSeconds,
                        onChange: e => setRefreshSeconds(Number(e.target.value) || 900),
                    }),
                    'Seconds, at least 60. This is how long a rotated secret takes to '
                    + 'reach running channels.'),
                Field('If a vault cannot be reached',
                    Check(stale, 'Keep serving the last value that was read', setStale),
                    'On by default. The credential has not changed — only our ability '
                    + 'to re-read it — so channels keep working through a vault '
                    + 'outage. Switch off where a revoked secret must stop being usable '
                    + 'within one refresh interval.'),
                Field('Event log',
                    Check(events, 'Record a secret that cannot be read', setEvents),
                    'Writes into the engine’s own event log, where alerts can see it.'),
            ]),
            h('div', { key: 'b', style: { marginTop: '9px' } },
                Button('Save settings', async () => {
                    setBusy(true);
                    try {
                        const result = await call('POST', '/settings', {
                            namespace,
                            refreshIntervalSeconds: String(refreshSeconds),
                            serveStaleOnFailure: String(stale),
                            writeServerEvents: String(events),
                        });
                        const notes = Array.isArray(result.notes) ? result.notes
                            : (result.notes ? [result.notes] : ['Settings saved.']);
                        props.onSaved(notes);
                    } catch (err) {
                        props.onError(err.message);
                    } finally {
                        setBusy(false);
                    }
                }, { primary: true, disabled: busy })),
        ]);
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------
    /*
     * Each registration is attempted independently.
     *
     * The shell calls register() once and lets an exception propagate, so a fault
     * part-way through leaves whatever ran before it registered and silently drops
     * everything after -- which in the git sync plugin meant a sidebar item vanishing
     * with nothing on the page to say why. Isolating each one turns that into a
     * console warning and a single missing item.
     */
    const safely = (label, fn) => {
        try {
            fn();
        } catch (err) {
            console.warn('[keystore] could not register ' + label, err);
        }
    };

    safely('icon', () => {
        platform.registerIcon('key-store', ICON_KEY);
    });

    safely('key store view', () => {
        platform.registerView('/key-store', platform.reactView(KeyStoreView), {
            title: 'Key Store',
        });
        // The label carries the fault count as of page load. The nav registry is read
        // once when the shell mounts and mutating a registered label does not
        // re-render, so it cannot tick up live; the page itself is current.
        platform.registerNavItem({
            id: 'key-store',
            label: navLabel(BOOT),
            icon: 'key-store',
            path: '/key-store',
            section: 'Plugins',
            order: 75,
        });
    });
}
