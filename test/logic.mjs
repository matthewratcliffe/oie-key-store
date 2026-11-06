/*
 * The pure helpers out of webadmin/web/plugin.js, so they can be tested without
 * a browser or a React runtime.
 *
 * Copied rather than imported, the same arrangement the Backup / Git Sync /
 * Volume Monitor extensions use. decode/decodeEntry/encodeMap/ref/directRef/
 * navLabel/parseStatus/parseConnection/parseDirect/parseBinding/typeLabel/
 * suggestedPrefix/testerWarning and the TYPES and SUGGESTED_PREFIX tables are
 * copied verbatim; problemText and authModeHint are lifted out of register()'s
 * closure unchanged. since() reads Date.now() in plugin.js; here it takes an
 * injected `now` so the thresholds are deterministic under test.
 */

export function decode(node) {
    if (node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(decode);

    const keys = Object.keys(node);

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

export function decodeEntry(entry) {
    if (entry === null || typeof entry !== 'object') return [String(entry), null];
    const props = Object.keys(entry);
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

export function encodeMap(obj) {
    const esc = v => String(v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    const entries = Object.keys(obj)
        .filter(k => obj[k] !== undefined && obj[k] !== null)
        .map(k => `<entry><string>${esc(k)}</string><string>${esc(obj[k])}</string></entry>`)
        .join('');
    return `<map>${entries}</map>`;
}

/*
 * A placeholder as it is written in a connector field. Built by concatenation
 * because ${...} means substitution to both JavaScript and Velocity.
 */
export function ref(namespace, name) {
    return '${' + namespace + '.' + name + '}';
}

export function directRef(prefix, secretId, field) {
    let out = '${' + prefix + "['" + secretId + "']";
    if (field) {
        out += /^[A-Za-z][A-Za-z0-9_]*$/.test(field) ? '.' + field : "['" + field + "']";
    }
    return out + '}';
}

export const SUGGESTED_PREFIX = {
    AZURE_KEY_VAULT: 'Azure',
    AWS_SECRETS_MANAGER: 'AWS',
    ONEPASSWORD_CONNECT: 'OnePassword',
    BITWARDEN_SECRETS_MANAGER: 'Bitwarden',
};

export function suggestedPrefix(type, taken) {
    const name = SUGGESTED_PREFIX[type] || '';
    return name && !(taken || []).includes(name) ? name : '';
}

export function testerWarning(connection, result) {
    if (!connection || !result || result.placeholder) return null;
    const name = connection.name || connection.label || 'this vault';
    if (connection.enabled === false) {
        return `Channels cannot read this secret: the vault "${name}" is switched off.`;
    }
    if (!connection.referencePrefix) {
        return 'Channels cannot read this secret as ${…}: the vault "' + name + '" has '
            + 'no direct reference name. Set one in the vault’s editor, or add a '
            + 'binding for this secret.';
    }
    return null;
}

export function navLabel(boot) {
    if (!boot || boot.ok === false) return 'Key Store';
    const faults = Number(boot.faults) || 0;
    return faults > 0 ? `Key Store (${faults})` : 'Key Store';
}

export const TYPES = [
    { token: 'AZURE_KEY_VAULT', label: 'Azure Key Vault' },
    { token: 'AWS_SECRETS_MANAGER', label: 'AWS Secrets Manager' },
    { token: 'ONEPASSWORD_CONNECT', label: '1Password Connect' },
    { token: 'BITWARDEN_SECRETS_MANAGER', label: 'Bitwarden Secrets Manager' },
];

export function parseStatus(row) {
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

export function parseConnection(row) {
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
        referencePrefix: f[19] || '',
    };
}

export function parseDirect(row) {
    const f = String(row).split('	');
    return {
        prefix: f[0] || '',
        secretId: f[1] || '',
        state: f[2] || 'OK',
        detail: f[3] || '',
        valueAt: Number(f[4]) || 0,
        checkedAt: Number(f[5]) || 0,
        version: f[6] || '',
        length: Number(f[7]) || 0,
        placeholder: f[8] || '',
    };
}

export function parseBinding(row) {
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

export function typeLabel(token) {
    const found = TYPES.find(t => t.token === token);
    return found ? found.label : token;
}

export function since(epochMs, now = Date.now()) {
    if (!epochMs) return '';
    const seconds = Math.max(0, Math.round((now - epochMs) / 1000));
    if (seconds < 90) return 'just now';
    const minutes = Math.round(seconds / 60);
    if (minutes < 90) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 36) return `${hours} h ago`;
    return `${Math.round(hours / 24)} d ago`;
}

/* Turns a rejected save into one readable string, problems included. */
export function problemText(result) {
    const problems = result && result.problems;
    const list = Array.isArray(problems) ? problems : (problems ? [problems] : []);
    const head = (result && result.error) || 'That could not be saved.';
    return list.length ? `${head}\n• ${list.join('\n• ')}` : head;
}

/* What each auth mode needs of the environment. */
export function authModeHint(type, mode) {
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
