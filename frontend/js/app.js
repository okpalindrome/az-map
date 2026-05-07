/**
 * Main app controller.
 */
const App = (() => {
  let currentScanId = null;
  let activeView = 'graph';

  // ── Startup ────────────────────────────────
  async function init() {
    GraphView.init();
    TableView.init();
    _bindToolbar();
    _bindFilters();
    _bindLegend();
    _bindAttackPathPanel();
    _bindDiffModal();
    _bindTenantModal();
    await Promise.all([_loadScanList(), _loadTenantList()]);
    _showWelcome(true);
  }

  function _bindTenantModal() {
    document.getElementById('btn-add-tenant')?.addEventListener('click', () => _openTenantModal());
    document.getElementById('btn-tenant-cancel')?.addEventListener('click', _closeTenantModal);
    document.getElementById('btn-tenant-save')?.addEventListener('click', _saveTenant);
    document.getElementById('tenant-modal')?.addEventListener('click', (e) => {
      if (e.target === document.getElementById('tenant-modal')) _closeTenantModal();
    });
  }

  // ── Toolbar ────────────────────────────────
  function _bindToolbar() {
    document.getElementById('btn-scan').addEventListener('click', _startScan);
    document.getElementById('sub-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') _startScan();
    });

    document.querySelectorAll('.view-tab').forEach(btn => {
      btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    document.getElementById('btn-refresh').addEventListener('click', () => {
      if (currentScanId) _loadGraph(currentScanId);
    });
    document.getElementById('btn-fit').addEventListener('click', () => GraphView.fitView());

    // Export buttons
    ['json', 'csv', 'html', 'paths'].forEach(fmt => {
      const btn = document.getElementById(`btn-export-${fmt}`);
      if (btn) btn.addEventListener('click', () => {
        if (!currentScanId) return;
        window.open(API.exportUrl(currentScanId, fmt), '_blank');
      });
    });

    // Graph controls
    document.getElementById('gc-zoomin').addEventListener('click', () => GraphView.zoomIn());
    document.getElementById('gc-zoomout').addEventListener('click', () => GraphView.zoomOut());
    document.getElementById('gc-fit').addEventListener('click', () => GraphView.fitView());
    document.getElementById('gc-reset').addEventListener('click', () => GraphView.resetLayout());

    // Edge label toggle
    const edgeToggle = document.getElementById('toggle-edge-labels');
    if (edgeToggle) {
      edgeToggle.addEventListener('change', (e) => GraphView.toggleEdgeLabels(e.target.checked));
    }
  }

  // ── Filters ────────────────────────────────
  function _bindFilters() {
    const debounce = (fn, ms) => { let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); }; };

    document.getElementById('search-input').addEventListener('input',
      debounce(() => { if (currentScanId) _applyFilters(); }, 400)
    );

    document.querySelectorAll('.filter-cb').forEach(cb => {
      cb.addEventListener('change', () => { if (currentScanId) _applyFilters(); });
    });
  }

  function _getFilterParams() {
    const types = [...document.querySelectorAll('.filter-cb[data-group="type"]:checked')]
      .map(cb => cb.value).join(',');
    const risks = [...document.querySelectorAll('.filter-cb[data-group="risk"]:checked')]
      .map(cb => cb.value).join(',');
    const search = document.getElementById('search-input').value.trim();
    return {
      node_types: types || undefined,
      risk_levels: risks || undefined,
      search: search || undefined,
    };
  }

  async function _applyFilters() {
    if (!currentScanId) return;
    const params = _getFilterParams();
    try {
      const stats = await GraphView.load(currentScanId, params);
      _updateStats(stats);
      if (activeView === 'table') TableView.render(currentScanId);
    } catch (e) {
      console.error('Filter error:', e);
    }
  }

  // ── Legend ─────────────────────────────────
  function _bindLegend() {
    const toggle = document.getElementById('legend-toggle');
    const body = document.getElementById('legend-body');
    if (toggle) toggle.addEventListener('click', () => {
      const v = body.style.display === 'none';
      body.style.display = v ? '' : 'none';
    });
  }

  // ── Scan start ──────────────────────────────
  async function _startScan() {
    const subId = document.getElementById('sub-input').value.trim();
    if (!subId) {
      document.getElementById('sub-input').focus();
      return;
    }
    const btn = document.getElementById('btn-scan');
    btn.disabled = true;
    btn.textContent = 'Starting…';

    try {
      const scan = await API.startScan(subId);
      _setStatus('running', 'Scan running…');
      _showProgress(true, 0, 'Initializing…', 'init');
      _showWelcome(false);

      API.streamScan(scan.scan_id,
        (evt) => {
          const pct = evt.total > 0 ? (evt.current / evt.total) * 100 : 20;
          _showProgress(true, pct, evt.message || '', evt.phase || '');
        },
        async (final) => {
          _showProgress(false);
          btn.disabled = false;
          btn.textContent = 'Scan';
          if (final.phase === 'error') {
            _setStatus('error', 'Scan failed');
            alert('Scan failed: ' + (final.message || 'Unknown error'));
          } else {
            _setStatus('done', 'Scan complete');
            await _loadScanList();
            await _selectScan(scan.scan_id);
          }
        }
      );
      await _loadScanList();
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Scan';
      alert('Failed to start scan: ' + e.message);
    }
  }

  // ── Scan list ──────────────────────────────
  async function _loadScanList() {
    try {
      const scans = await API.listScans();
      const list = document.getElementById('scan-list');
      if (scans.length === 0) {
        list.innerHTML = '<p style="padding:12px; color:#999; font-size:12px;">No scans yet.</p>';
        return;
      }
      list.innerHTML = scans.map(s => `
        <div class="scan-item ${s.scan_id === currentScanId ? 'active' : ''}"
             data-id="${s.scan_id}">
          <div style="display:flex; align-items:baseline; gap:4px;">
            <div class="scan-item-name" style="flex:1;">${_esc(s.snapshot_label || s.subscription_name || s.subscription_id)}</div>
            ${s.status === 'completed'
              ? `<button class="scan-label-btn" data-id="${s.scan_id}" data-label="${_esc(s.snapshot_label||'')}"
                   title="Edit label" style="background:none;border:none;cursor:pointer;color:#ccc;font-size:11px;padding:0;flex-shrink:0;">✎</button>`
              : ''}
          </div>
          <div class="scan-item-meta">
            ${_fmtDate(s.started_at)} &nbsp;
            <span style="color:${s.status === 'completed' ? '#4CAF50' : s.status === 'failed' ? '#F44336' : '#7B68EE'};">
              ${s.status}
            </span>
          </div>
        </div>`).join('');
      list.querySelectorAll('.scan-item').forEach(item => {
        item.addEventListener('click', () => _selectScan(item.dataset.id));
      });
      list.querySelectorAll('.scan-label-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          _editSnapshotLabel(btn.dataset.id, btn.dataset.label);
        });
      });
    } catch (e) {
      console.error('Could not load scan list:', e);
    }
  }

  async function _selectScan(scanId) {
    currentScanId = scanId;
    document.querySelectorAll('.scan-item').forEach(el =>
      el.classList.toggle('active', el.dataset.id === scanId)
    );
    _showWelcome(false);
    _setStatus('running', 'Loading…');
    try {
      await _loadGraph(scanId);
      _setStatus('done', 'Loaded');
      if (activeView === 'table') TableView.render(scanId);
    } catch (e) {
      _setStatus('error', 'Failed to load');
      console.error(e);
    }
  }

  async function _loadGraph(scanId) {
    const params = _getFilterParams();
    const stats = await GraphView.load(scanId, params);
    _updateStats(stats);

    // Load findings summary for sidebar chips
    try {
      const summary = await API.getFindingsSummary(scanId);
      _updateFindingChips(summary.by_severity || {});
    } catch (_) {}
  }

  // ── Stats / chips ──────────────────────────
  function _updateStats(stats) {
    const el = document.getElementById('graph-stats-row');
    if (!el || !stats) return;
    el.innerHTML = `
      <span class="stat-chip">${stats.total_nodes} nodes</span>
      <span class="stat-chip">${stats.total_edges} edges</span>
      ${stats.critical_nodes ? `<span class="stat-chip critical">${stats.critical_nodes} critical</span>` : ''}
      ${stats.risky_nodes ? `<span class="stat-chip risky">${stats.risky_nodes} risky</span>` : ''}
    `;
  }

  function _updateFindingChips(bySev) {
    const el = document.getElementById('finding-chips');
    if (!el) return;
    const items = ['critical', 'high', 'medium', 'low']
      .filter(s => bySev[s] > 0)
      .map(s => `<span class="stat-chip ${s}">${bySev[s]} ${s}</span>`)
      .join('');
    el.innerHTML = items || '';
  }

  // ── View switching ─────────────────────────
  function switchView(view) {
    activeView = view;
    document.querySelectorAll('.view-tab').forEach(btn =>
      btn.classList.toggle('active', btn.dataset.view === view)
    );
    document.getElementById('graph-view').classList.toggle('active', view === 'graph');
    document.getElementById('table-view').classList.toggle('active', view === 'table');
    document.getElementById('dashboard-view').classList.toggle('active', view === 'dashboard');

    const graphControls = document.getElementById('graph-controls');
    const legend = document.getElementById('legend');
    const pathPanel = document.getElementById('attack-path-panel');
    if (graphControls) graphControls.style.display = view === 'graph' ? '' : 'none';
    if (legend) legend.style.display = view === 'graph' ? '' : 'none';
    // Hide attack path panel when not in graph view
    if (pathPanel && view !== 'graph') pathPanel.classList.remove('visible');

    if (view === 'table' && currentScanId) {
      TableView.render(currentScanId);
    } else if (view === 'dashboard' && currentScanId) {
      DashboardView.render(currentScanId);
    }
  }

  // ── Attack path panel ──────────────────────
  function _bindAttackPathPanel() {
    const btnPaths = document.getElementById('btn-paths');
    const panel = document.getElementById('attack-path-panel');
    const closeBtn = document.getElementById('path-panel-close');

    btnPaths?.addEventListener('click', () => {
      panel.classList.toggle('visible');
    });
    closeBtn?.addEventListener('click', () => panel.classList.remove('visible'));

    document.getElementById('btn-find-paths')?.addEventListener('click', _findPaths);
    document.getElementById('btn-global-admin-paths')?.addEventListener('click', _findGlobalAdminPaths);
  }

  async function _findPaths() {
    if (!currentScanId) return;
    const fromVal = document.getElementById('path-from').value.trim();
    const toVal   = document.getElementById('path-to').value.trim();
    const results = document.getElementById('path-results');
    results.innerHTML = '<p style="color:#999; font-size:12px;">Searching…</p>';

    try {
      const params = {};
      if (fromVal) params.from_node = fromVal;
      if (toVal)   params.to_node   = toVal;
      const data = await API.getAttackPaths(currentScanId, params);
      _renderPathResults(data.paths || []);
    } catch (e) {
      results.innerHTML = `<p style="color:#F44336; font-size:12px;">Error: ${e.message}</p>`;
    }
  }

  async function _findGlobalAdminPaths() {
    if (!currentScanId) return;
    document.getElementById('path-from').value = '';
    document.getElementById('path-to').value = '';
    const results = document.getElementById('path-results');
    results.innerHTML = '<p style="color:#999; font-size:12px;">Finding Global Admin paths…</p>';
    try {
      const data = await API.getAttackPaths(currentScanId, {});
      _renderPathResults(data.paths || []);
    } catch (e) {
      results.innerHTML = `<p style="color:#F44336; font-size:12px;">Error: ${e.message}</p>`;
    }
  }

  function _renderPathResults(paths) {
    const results = document.getElementById('path-results');
    if (!paths.length) {
      results.innerHTML = '<p style="color:#999; font-size:12px; margin-top:8px;">No paths found.</p>';
      return;
    }
    results.innerHTML = paths.slice(0, 20).map((p, i) => {
      const pathIds = p.path || [];
      const src = p.source_name || (p.path_details?.[0]?.name) || p.source || '';
      const tgt = p.target || '';
      const hops = p.length || (pathIds.length - 1);
      return `<div class="path-result-item" data-idx="${i}">
        <span class="path-hops">${hops}h</span>
        <strong>${_esc(src)}</strong>
        <span style="color:#999;"> → </span>
        <span>${_esc(tgt.split('/').pop() || tgt)}</span>
      </div>`;
    }).join('');

    results.querySelectorAll('.path-result-item').forEach((el, i) => {
      el.addEventListener('click', () => {
        const p = paths[i];
        const pathIds = p.path || (p.path_details || []).map(s => s.node_id);
        if (pathIds.length) GraphView.highlightPath(pathIds);
      });
    });
  }

  // ── Diff modal ─────────────────────────────
  function _bindDiffModal() {
    document.getElementById('btn-diff')?.addEventListener('click', _openDiff);
    document.getElementById('diff-close')?.addEventListener('click', () => {
      document.getElementById('diff-panel').classList.remove('open');
    });
    document.getElementById('diff-panel')?.addEventListener('click', (e) => {
      if (e.target === document.getElementById('diff-panel'))
        document.getElementById('diff-panel').classList.remove('open');
    });
    document.getElementById('btn-run-diff')?.addEventListener('click', _runDiff);
  }

  async function _openDiff() {
    const panel = document.getElementById('diff-panel');
    panel.classList.add('open');
    // Populate selects with completed scans for current subscription
    const selA = document.getElementById('diff-scan-a');
    const selB = document.getElementById('diff-scan-b');
    document.getElementById('diff-results').innerHTML = '';

    if (!currentScanId) return;
    try {
      // Get the subscription_id of current scan
      const scan = await API.getScan(currentScanId);
      const snapshots = await API.listSnapshots(scan.subscription_id);
      const opts = snapshots.map(s =>
        `<option value="${s.scan_id}">${_esc(s.snapshot_label || s.scan_id.substring(0,8))} — ${_fmtDate(s.completed_at)}</option>`
      ).join('');
      selA.innerHTML = '<option value="">Select baseline…</option>' + opts;
      selB.innerHTML = '<option value="">Select current…</option>' + opts;
      // Pre-select: current scan as B, previous as A
      if (snapshots.length >= 2) {
        selB.value = snapshots[0].scan_id;
        selA.value = snapshots[1].scan_id;
      } else if (snapshots.length === 1) {
        selB.value = snapshots[0].scan_id;
      }
    } catch (e) {
      console.error('Could not load snapshots:', e);
    }
  }

  async function _runDiff() {
    const scanA = document.getElementById('diff-scan-a').value;
    const scanB = document.getElementById('diff-scan-b').value;
    const results = document.getElementById('diff-results');
    if (!scanA || !scanB) { results.innerHTML = '<p style="color:#F44336;">Select both scans.</p>'; return; }
    if (scanA === scanB)  { results.innerHTML = '<p style="color:#F44336;">Select two different scans.</p>'; return; }

    results.innerHTML = '<p style="color:#999;">Comparing…</p>';
    try {
      const diff = await API.diffScans(scanA, scanB);
      results.innerHTML = _renderDiff(diff);

      // Apply diff overlay to graph
      if (activeView === 'graph') {
        GraphView.applyDiffOverlay({
          new:      new Set(diff.new_nodes.map(n => n.node_id)),
          removed:  new Set(diff.removed_nodes.map(n => n.node_id)),
          riskUp:   new Set(diff.risk_changed.filter(r => r.delta > 0).map(r => r.node_id)),
          riskDown: new Set(diff.risk_changed.filter(r => r.delta < 0).map(r => r.node_id)),
        });
      }
    } catch (e) {
      results.innerHTML = `<p style="color:#F44336;">Error: ${e.message}</p>`;
    }
  }

  function _renderDiff(diff) {
    const s = diff.summary;
    const chips = [
      s.new_nodes     ? `<span class="diff-chip new-node">+${s.new_nodes} new resources</span>` : '',
      s.removed_nodes ? `<span class="diff-chip del-node">-${s.removed_nodes} removed</span>` : '',
      s.risk_increased? `<span class="diff-chip risk-up">↑ ${s.risk_increased} risk increased</span>` : '',
      s.risk_decreased? `<span class="diff-chip risk-down">↓ ${s.risk_decreased} risk decreased</span>` : '',
      s.new_findings  ? `<span class="diff-chip new-finding">+${s.new_findings} new findings</span>` : '',
      s.resolved_findings? `<span class="diff-chip resolved">✓ ${s.resolved_findings} resolved</span>` : '',
    ].filter(Boolean).join('');

    let html = `
      <div style="margin-bottom:8px; font-size:12px; color:#666;">
        Comparing: <strong>${_esc(diff.scan_a.label || diff.scan_a.id.substring(0,8))}</strong>
        → <strong>${_esc(diff.scan_b.label || diff.scan_b.id.substring(0,8))}</strong>
      </div>
      <div class="diff-summary-row">${chips || '<span style="color:#999; font-size:12px;">No differences found.</span>'}</div>`;

    if (diff.new_findings.length) {
      const SEV = { critical:'#F44336', high:'#FF9800', medium:'#FFC107', low:'#4CAF50' };
      html += `<div class="diff-section">
        <div class="diff-section-title">New Findings (${diff.new_findings.length})</div>
        ${diff.new_findings.slice(0,10).map(f => `
          <div class="diff-item new">
            <span style="font-weight:600; color:${SEV[f.severity]||'#999'}; width:50px; flex-shrink:0;">${f.severity}</span>
            <span>${_esc(f.title)}</span>
          </div>`).join('')}
      </div>`;
    }
    if (diff.risk_changed.length) {
      html += `<div class="diff-section">
        <div class="diff-section-title">Risk Changes (${diff.risk_changed.length})</div>
        ${diff.risk_changed.slice(0,10).map(r => `
          <div class="diff-item ${r.delta > 0 ? 'chg' : 'new'}">
            <span style="width:60px; flex-shrink:0; font-weight:600; color:${r.delta>0?'#E65100':'#1565C0'};">${r.delta>0?'+':''}${r.delta}</span>
            <span>${_esc(r.display_name || r.name)}</span>
            <span style="margin-left:auto; font-size:11px; color:#999;">${r.risk_level_before} → ${r.risk_level_after}</span>
          </div>`).join('')}
      </div>`;
    }
    if (diff.resolved_findings.length) {
      html += `<div class="diff-section">
        <div class="diff-section-title">Resolved Findings (${diff.resolved_findings.length})</div>
        ${diff.resolved_findings.slice(0,5).map(f => `
          <div class="diff-item new" style="background:#F1F8E9;">
            <span>✓ ${_esc(f.title)}</span>
          </div>`).join('')}
      </div>`;
    }
    return html;
  }

  // ── Progress — slim top bar (pip-style) ───────────────────────
  function _showProgress(visible, pct = 0, msg = '', phase = '') {
    const bar = document.getElementById('top-progress-bar');
    if (!bar) return;

    if (visible) {
      bar.classList.add('visible');
      bar.style.width = `${Math.max(pct, 2)}%`;
      // Show progress in status area instead of blocking the UI
      const label = phase && phase !== 'done' && phase !== 'error'
        ? `${phase} — ${msg}`
        : msg;
      _setStatus('running', label);
    } else {
      // Animate to 100% then fade out
      bar.style.width = '100%';
      setTimeout(() => {
        bar.classList.remove('visible');
        setTimeout(() => { bar.style.width = '0%'; }, 220);
      }, 350);
    }
  }

  function _showWelcome(visible) {
    const el = document.getElementById('welcome');
    if (el) el.style.display = visible ? '' : 'none';
  }

  // ── Status bar ─────────────────────────────
  function _setStatus(state, msg) {
    const dot = document.querySelector('#scan-status .status-dot');
    const text = document.getElementById('status-text');
    if (dot) dot.className = `status-dot ${state}`;
    if (text) text.textContent = msg;
  }

  // ── Tenant management ──────────────────────
  let _editingTenantId = null;

  async function _loadTenantList() {
    try {
      const tenants = await API.listTenants();
      const el = document.getElementById('tenant-list');
      if (!el) return;
      if (tenants.length === 0) {
        el.innerHTML = '<p style="font-size:11px; color:#bbb; padding:4px 0;">No tenants configured.</p>';
        return;
      }
      el.innerHTML = tenants.map(t => `
        <div class="tenant-item" data-id="${t.id}">
          <div style="display:flex; align-items:center; gap:6px;">
            <div style="flex:1; min-width:0;">
              <div style="font-weight:500; font-size:12px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${_esc(t.display_name)}</div>
              <div style="font-size:10px; color:#999;">${(t.subscription_ids||[]).length} sub(s)</div>
            </div>
            <button class="tenant-edit-btn" data-id="${t.id}" title="Edit" style="background:none; border:none; cursor:pointer; color:#bbb; font-size:13px; padding:2px;">✎</button>
            <button class="tenant-del-btn"  data-id="${t.id}" title="Delete" style="background:none; border:none; cursor:pointer; color:#bbb; font-size:13px; padding:2px;">✕</button>
          </div>
        </div>`).join('');

      el.querySelectorAll('.tenant-edit-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const t = tenants.find(x => x.id === btn.dataset.id);
          if (t) _openTenantModal(t);
        });
      });
      el.querySelectorAll('.tenant-del-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          if (!confirm('Delete this tenant config?')) return;
          await API.deleteTenant(btn.dataset.id);
          _loadTenantList();
        });
      });
    } catch (e) {
      console.error('Could not load tenants:', e);
    }
  }

  function _openTenantModal(existing = null) {
    _editingTenantId = existing?.id || null;
    document.getElementById('tenant-modal-title').textContent = existing ? 'Edit Tenant' : 'Add Tenant';
    document.getElementById('t-name').value      = existing?.display_name || '';
    document.getElementById('t-tenant-id').value = existing?.tenant_id || '';
    document.getElementById('t-subs').value      = (existing?.subscription_ids || []).join('\n');
    document.getElementById('t-notes').value     = existing?.notes || '';
    const modal = document.getElementById('tenant-modal');
    modal.style.display = 'flex';
    setTimeout(() => document.getElementById('t-name').focus(), 50);
  }

  function _closeTenantModal() {
    document.getElementById('tenant-modal').style.display = 'none';
    _editingTenantId = null;
  }

  async function _saveTenant() {
    const name = document.getElementById('t-name').value.trim();
    if (!name) { document.getElementById('t-name').focus(); return; }
    const body = {
      display_name: name,
      tenant_id: document.getElementById('t-tenant-id').value.trim() || null,
      subscription_ids: document.getElementById('t-subs').value
        .split('\n').map(s => s.trim()).filter(Boolean),
      notes: document.getElementById('t-notes').value.trim() || null,
    };
    try {
      if (_editingTenantId) {
        await API.updateTenant(_editingTenantId, body);
      } else {
        await API.createTenant(body);
      }
      _closeTenantModal();
      _loadTenantList();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  // ── Scan history: inline snapshot label editing ────────────────────────────
  async function _editSnapshotLabel(scanId, currentLabel) {
    const newLabel = prompt('Snapshot label:', currentLabel || '');
    if (newLabel === null) return; // cancelled
    await API.setSnapshotLabel(scanId, newLabel.trim() || scanId.substring(0, 8));
    await _loadScanList();
  }

  // ── Helpers ────────────────────────────────
  function _fmtDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function _esc(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  return { init, switchView };
})();


// ── Detail Panel ────────────────────────────────────────────────────────────
const DetailPanel = (() => {
  function show(scanId, nodeId) {
    API.getNodeDetail(scanId, nodeId).then(node => {
      document.getElementById('detail-title').textContent = node.display_name || node.name;
      document.getElementById('detail-type').textContent = node.node_type.replace(/_/g, ' ');

      const body = document.getElementById('detail-body');
      body.innerHTML = _render(node);
      document.getElementById('detail-panel').classList.add('open');

      // Navigate to related node on click
      body.querySelectorAll('.rel-item[data-nodeid]').forEach(el => {
        el.addEventListener('click', () => {
          GraphView.highlightNode(el.dataset.nodeid);
          show(scanId, el.dataset.nodeid);
        });
      });
    }).catch(console.error);
  }

  function close() {
    document.getElementById('detail-panel').classList.remove('open');
  }

  function _render(node) {
    const riskColor = { critical: '#F44336', risky: '#FF9800', safe: '#4CAF50' }[node.risk_level] || '#9E9E9E';
    const props = node.properties || {};

    let html = `
      <div class="detail-section">
        <div class="detail-section-title">Risk</div>
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
          <div style="font-size:28px; font-weight:700; color:${riskColor};">${node.risk_score}</div>
          <div>
            <div style="font-weight:600; color:${riskColor}; text-transform:capitalize;">${node.risk_level}</div>
            <div style="font-size:11px; color:#999;">/ 10</div>
          </div>
        </div>
        ${node.risk_reasons && node.risk_reasons.length ? `
          <ul class="risk-reasons">
            ${node.risk_reasons.map(r => `<li>${_esc(r)}</li>`).join('')}
          </ul>` : ''}
      </div>`;

    // Properties section — show key fields
    const keyFields = _getKeyFields(node.node_type, props);
    if (keyFields.length) {
      html += `<div class="detail-section">
        <div class="detail-section-title">Properties</div>
        ${keyFields.map(([k, v]) => `
          <div class="detail-row">
            <span class="detail-key">${_esc(k)}</span>
            <span class="detail-val">${_esc(String(v ?? '—'))}</span>
          </div>`).join('')}
      </div>`;
    }

    // Relationships
    const rels = node.relationships || [];
    if (rels.length) {
      html += `<div class="detail-section">
        <div class="detail-section-title">Relationships (${rels.length})</div>
        ${rels.slice(0, 25).map(r => `
          <div class="rel-item" data-nodeid="${_esc(r.other_node_id)}">
            <span style="color:#999; font-size:10px;">${r.direction === 'outbound' ? '→' : '←'}</span>
            <span class="rel-arrow">${_esc(r.edge_type.replace(/_/g, ' '))}</span>
            <span class="rel-name">${_esc(r.other_node_name)}</span>
            <div style="font-size:10px; color:#bbb;">${_esc(r.other_node_type.replace(/_/g, ' '))}</div>
          </div>`).join('')}
        ${rels.length > 25 ? `<div style="font-size:11px; color:#999; padding:4px;">+${rels.length - 25} more</div>` : ''}
      </div>`;
    }

    return html;
  }

  function _getKeyFields(nodeType, props) {
    const common = [];
    if (props.upn) common.push(['UPN', props.upn]);
    if (props.mail) common.push(['Email', props.mail]);
    if (props.app_id) common.push(['App ID', props.app_id]);
    if (props.sp_type) common.push(['SP Type', props.sp_type]);
    if (props.location) common.push(['Location', props.location]);
    if (props.resource_group) common.push(['Resource Group', props.resource_group]);
    if (props.kind) common.push(['Kind', props.kind]);
    if (props.state) common.push(['State', props.state]);
    if (props.sku) common.push(['SKU', props.sku]);
    if (props.vault_uri) common.push(['Vault URI', props.vault_uri]);
    if (props.enable_rbac_authorization !== undefined) common.push(['RBAC Auth', props.enable_rbac_authorization ? 'Yes' : 'No (access policies)']);
    if (props.allow_blob_public_access !== undefined) common.push(['Public Blob', props.allow_blob_public_access ? '⚠ Yes' : 'No']);
    if (props.https_only !== undefined) common.push(['HTTPS Only', props.https_only ? 'Yes' : '⚠ No']);
    if (props.identity_type) common.push(['Identity', props.identity_type]);
    if (props.has_key_credentials !== undefined) common.push(['Key Creds', props.has_key_credentials ? `Yes (${props.key_credential_count})` : 'No']);
    if (props.has_password_credentials !== undefined) common.push(['Pwd Creds', props.has_password_credentials ? `Yes (${props.password_credential_count})` : 'No']);
    if (props.account_enabled !== undefined) common.push(['Enabled', props.account_enabled ? 'Yes' : 'No']);
    return common;
  }

  function _esc(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  return { show, close };
})();


// ── Tooltip ─────────────────────────────────────────────────────────────────
const Tooltip = (() => {
  const el = () => document.getElementById('tooltip');

  function show(text, x, y) {
    const t = el();
    if (!t) return;
    t.textContent = text;
    t.style.display = 'block';
    t.style.left = `${Math.min(x, window.innerWidth - 280)}px`;
    t.style.top = `${Math.max(y - 40, 4)}px`;
  }

  function hide() {
    const t = el();
    if (t) t.style.display = 'none';
  }

  return { show, hide };
})();


// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());

// Close detail panel button
document.getElementById('detail-close')?.addEventListener('click', () => DetailPanel.close());
