/**
 * API client — thin wrappers around fetch().
 */
const API = {
  _base: '',

  async _req(method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(this._base + path, opts);
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(err.detail || `HTTP ${r.status}`);
    }
    return r.json();
  },

  get: (path) => API._req('GET', path, null),
  post: (path, body) => API._req('POST', path, body),
  del: (path) => API._req('DELETE', path, null),

  // -- Scan --
  startScan: (subscriptionId, label) =>
    API.post('/api/scan/start', { subscription_id: subscriptionId, snapshot_label: label || null }),

  listScans: () => API.get('/api/scan/'),
  getScan: (id) => API.get(`/api/scan/${id}`),
  deleteScan: (id) => API.del(`/api/scan/${id}`),

  streamScan(scanId, onEvent, onDone) {
    const es = new EventSource(`/api/scan/stream/${scanId}`);
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      onEvent(data);
      if (data.phase === 'done' || data.phase === 'error') {
        es.close();
        onDone(data);
      }
    };
    es.onerror = () => { es.close(); onDone({ phase: 'error', message: 'Stream lost' }); };
    return es;
  },

  // -- Graph --
  getGraphElements: (scanId, params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== ''))
    ).toString();
    return API.get(`/api/graph/${scanId}/elements${qs ? '?' + qs : ''}`);
  },
  getNodeDetail: (scanId, nodeId) => API.get(`/api/graph/${scanId}/node/${encodeURIComponent(nodeId)}`),
  getGraphStats: (scanId) => API.get(`/api/graph/${scanId}/stats`),
  getAttackPaths: (scanId, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return API.get(`/api/graph/${scanId}/paths?${qs}`);
  },

  // -- Findings --
  getFindings: (scanId, params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== ''))
    ).toString();
    return API.get(`/api/findings/${scanId}${qs ? '?' + qs : ''}`);
  },
  getFindingsSummary: (scanId) => API.get(`/api/findings/${scanId}/summary`),

  // -- Export --
  exportUrl: (scanId, format) => `/api/export/${scanId}/${format}`,

  // -- Snapshot / Diff --
  listSnapshots: (subscriptionId) => API.get(`/api/snapshot/list/${subscriptionId}`),
  diffScans: (scanA, scanB) => API.get(`/api/snapshot/diff?scan_a=${scanA}&scan_b=${scanB}`),
  setSnapshotLabel: (scanId, label) => API.post(`/api/snapshot/label/${scanId}`, { label }),

  // -- Tenant config --
  listTenants: () => API.get('/api/tenant/'),
  createTenant: (body) => API.post('/api/tenant/', body),
  updateTenant: (id, body) => API._req('PUT', `/api/tenant/${id}`, body),
  deleteTenant: (id) => API.del(`/api/tenant/${id}`),
};
