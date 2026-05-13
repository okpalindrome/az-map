/**
 * Main app controller.
 */
const App = (() => {
  let currentScanId = null;
  let activeView = 'dashboard';
  let _currentUser = null;

  async function init() {
    GraphView.init();
    TableView.init();
    _bindToolbar();
    _bindFilters();
    _bindLegend();
    _bindAttackPathPanel();
    _bindDiffModal();
    _bindTenantModal();
    _bindImport();
    await Promise.all([_loadScanList(), _loadTenantList(), _loadSubscriptions()]);
    _showWelcome(true);
    // Hide graph-only controls on initial load (default view is dashboard)
    document.getElementById('graph-controls')?.style && (document.getElementById('graph-controls').style.display = 'none');
    document.getElementById('legend')?.style && (document.getElementById('legend').style.display = 'none');
    // Detect current az user in background
    API.getCurrentUser().then(u => { _currentUser = u; }).catch(() => {});
  }

  function _bindTenantModal() {
    document.getElementById('btn-add-tenant')?.addEventListener('click', () => _openTenantModal());
    document.getElementById('btn-tenant-cancel')?.addEventListener('click', _closeTenantModal);
    document.getElementById('btn-tenant-save')?.addEventListener('click', _saveTenant);
    document.getElementById('tenant-modal')?.addEventListener('click', (e) => {
      if (e.target === document.getElementById('tenant-modal')) _closeTenantModal();
    });
  }

  // ── Import JSON ────────────────────────────
  function _bindImport() {
    const btn = document.getElementById('btn-import');
    const inp = document.getElementById('import-file-input');
    if (!btn || !inp) return;

    btn.addEventListener('click', () => inp.click());

    inp.addEventListener('change', async () => {
      const file = inp.files?.[0];
      if (!file) return;
      inp.value = '';
      try {
        const text = await file.text();
        const json = JSON.parse(text);
        btn.disabled = true;
        btn.textContent = 'Importing…';
        const scan = await API.importScan(json);
        await _loadScanList();
        await _selectScan(scan.scan_id);
        _setStatus('done', 'Import complete');
      } catch (e) {
        alert('Import failed: ' + e.message);
        _setStatus('error', 'Import failed');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Import';
      }
    });
  }

  // ── Subscription select ────────────────────
  async function _loadSubscriptions() {
    const sel = document.getElementById('sub-select');
    const inp = document.getElementById('sub-input');
    if (!sel) return;

    try {
      const subs = await API.listSubscriptions();

      if (!Array.isArray(subs) || subs.length === 0) {
        sel.style.display = 'none';
        if (inp) inp.style.display = '';
        return;
      }

      // Build options using DOM properties — avoids any HTML-injection or
      // encoding issues that arise from injecting raw names into innerHTML.
      sel.innerHTML = '';
      subs.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.id || '';
        opt.textContent = s.name || s.id || '(unnamed)';
        if (s.is_default) opt.selected = true;
        sel.appendChild(opt);
      });
      const manual = document.createElement('option');
      manual.value = '';
      manual.textContent = '— Enter ID manually —';
      sel.appendChild(manual);

      sel.style.display = '';
      if (inp) inp.style.display = 'none';

      sel.addEventListener('change', () => {
        if (!sel.value) {
          sel.style.display = 'none';
          if (inp) { inp.style.display = ''; inp.focus(); }
        }
      });
    } catch (e) {
      console.warn('Could not load subscriptions:', e);
      sel.style.display = 'none';
      if (inp) inp.style.display = '';
    }
  }

  function _getSubId() {
    const sel = document.getElementById('sub-select');
    if (sel && sel.style.display !== 'none' && sel.value) return sel.value;
    return (document.getElementById('sub-input').value || '').trim();
  }

  function _getSubLabel() {
    const sel = document.getElementById('sub-select');
    if (sel && sel.style.display !== 'none' && sel.value) {
      const opt = sel.options[sel.selectedIndex];
      return opt ? opt.textContent.trim() : null;
    }
    return null;
  }

  // ── Toolbar ────────────────────────────────
  function _bindToolbar() {
    document.getElementById('btn-scan')?.addEventListener('click', _startScan);
    document.getElementById('sub-input')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') _startScan();
    });

    document.querySelectorAll('.view-tab').forEach(btn => {
      btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    document.getElementById('btn-refresh')?.addEventListener('click', () => {
      if (currentScanId) _loadGraph(currentScanId);
    });

    // Export buttons (JSON + CSV only)
    ['json', 'csv'].forEach(fmt => {
      document.getElementById(`btn-export-${fmt}`)?.addEventListener('click', () => {
        if (!currentScanId) return;
        window.open(API.exportUrl(currentScanId, fmt), '_blank');
      });
    });

    document.getElementById('gc-zoomin')?.addEventListener('click', () => GraphView.zoomIn());
    document.getElementById('gc-zoomout')?.addEventListener('click', () => GraphView.zoomOut());
    document.getElementById('gc-fit')?.addEventListener('click', () => GraphView.fitView());
    document.getElementById('gc-reset')?.addEventListener('click', () => GraphView.resetLayout());
    document.getElementById('toggle-edge-labels')?.addEventListener('change', (e) =>
      GraphView.toggleEdgeLabels(e.target.checked)
    );
  }

  // ── Filters ────────────────────────────────
  function _bindFilters() {
    const debounce = (fn, ms) => { let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); }; };
    // 600 ms debounce — enough time for the user to finish typing/clicking
    // before we hit the API and re-render the graph
    const debouncedApply = debounce(() => { if (currentScanId) _applyFilters(); }, 600);

    document.getElementById('search-input')?.addEventListener('input', debouncedApply);
    document.querySelectorAll('.filter-cb').forEach(cb => {
      cb.addEventListener('change', debouncedApply);
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
    const subId = _getSubId();
    if (!subId) {
      const sel = document.getElementById('sub-select');
      if (sel && sel.style.display !== 'none') sel.focus();
      else document.getElementById('sub-input').focus();
      return;
    }
    const btn = document.getElementById('btn-scan');
    btn.disabled = true;
    btn.textContent = 'Starting…';

    try {
      const scan = await API.startScan(subId, _getSubLabel());
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
      list.innerHTML = scans.map(s => {
        const isImported = (s.snapshot_label || '').startsWith('Imported:');
        return `
        <div class="scan-item ${s.scan_id === currentScanId ? 'active' : ''}"
             data-id="${s.scan_id}">
          <div style="display:flex; align-items:baseline; gap:4px;">
            <div class="scan-item-name" style="flex:1;">
              ${isImported ? '<span style="color:#7B68EE; font-size:10px;">↓</span> ' : ''}${_esc(s.snapshot_label || s.subscription_name || s.subscription_id)}
            </div>
            ${s.status === 'completed' && !isImported
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
        </div>`;
      }).join('');
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
      else if (activeView === 'dashboard') DashboardView.render(scanId);
      _loadOwnedList(scanId);
      // Auto-mark current user as owned if found
      _autoMarkCurrentUser(scanId);
    } catch (e) {
      _setStatus('error', 'Failed to load');
      console.error(e);
    }
  }

  async function _autoMarkCurrentUser(scanId) {
    if (!_currentUser) {
      try { _currentUser = await API.getCurrentUser(); } catch (_) { return; }
    }
    if (!_currentUser?.object_id) return;
    try {
      await API.setNodeOwned(scanId, _currentUser.object_id, true);
      GraphView.updateNodeOwned(_currentUser.object_id, true);
      _loadOwnedList(scanId);
    } catch (_) {
      // Node not in this scan (different subscription or no match)
    }
  }

  async function _loadOwnedList(scanId) {
    const section = document.getElementById('owned-section');
    const list = document.getElementById('owned-list');
    const countEl = document.getElementById('owned-count');
    if (!section || !list) return;

    // Always show the section once a scan is active so users know it exists
    section.style.display = '';

    try {
      const data = await API.getOwnedNodes(scanId);
      const nodes = data.owned_nodes || [];

      if (nodes.length === 0) {
        if (countEl) countEl.textContent = '';
        list.innerHTML = '<div style="font-size:11px; color:#bbb; padding:4px 0;">None yet — open a node and click Mark as Owned.</div>';
        return;
      }

      if (countEl) countEl.textContent = nodes.length;
      list.innerHTML = '';
      nodes.forEach(n => {
        const item = document.createElement('div');
        item.className = 'owned-item';
        item.dataset.nodeid = n.node_id;
        item.title = n.name || n.node_id;

        const dot = document.createElement('div');
        dot.className = 'owned-item-dot';

        const name = document.createElement('span');
        name.className = 'owned-item-name';
        name.textContent = n.name || n.node_id;

        const type = document.createElement('span');
        type.className = 'owned-item-type';
        type.textContent = (n.node_type || '').replace(/_/g, ' ');

        item.append(dot, name, type);
        item.addEventListener('click', () => {
          GraphView.highlightNode(n.node_id);
          DetailPanel.show(scanId, n.node_id);
        });
        list.appendChild(item);
      });
    } catch (_) {
      list.innerHTML = '<div style="font-size:11px; color:#bbb; padding:4px 0;">Could not load owned nodes.</div>';
    }
  }

  function refreshOwnedList() {
    if (currentScanId) _loadOwnedList(currentScanId);
  }

  function _showGraphLoading(visible, msg = 'Loading graph…') {
    const el = document.getElementById('graph-loading');
    if (!el) return;
    if (visible) {
      document.getElementById('graph-loading-msg').textContent = msg;
      el.style.display = 'flex';
    } else {
      el.style.display = 'none';
    }
  }

  // Serial counter — ensures rapid scan switches don't show stale loading states
  let _graphLoadSerial = 0;

  async function _loadGraph(scanId) {
    const serial = ++_graphLoadSerial;
    _showGraphLoading(true, 'Loading graph…');
    try {
      const params = _getFilterParams();
      const stats = await GraphView.load(scanId, params);
      if (serial !== _graphLoadSerial) return; // superseded by a later load
      _updateStats(stats);
      try {
        const summary = await API.getFindingsSummary(scanId);
        if (serial !== _graphLoadSerial) return;
        _updateFindingChips(summary.by_severity || {});
      } catch (_) {}
    } finally {
      if (serial === _graphLoadSerial) _showGraphLoading(false);
    }
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
    if (pathPanel && view !== 'graph') pathPanel.classList.remove('visible');

    if (view === 'graph') {
      // Run layout now if a load happened while the graph was hidden
      GraphView.runLayoutIfNeeded();
    } else if (view === 'table' && currentScanId) {
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

    btnPaths?.addEventListener('click', () => panel.classList.toggle('visible'));
    closeBtn?.addEventListener('click', () => panel.classList.remove('visible'));

    document.getElementById('btn-find-paths')?.addEventListener('click', _findPaths);
    document.getElementById('btn-global-admin-paths')?.addEventListener('click', _findGlobalAdminPaths);
    document.getElementById('btn-owned-paths')?.addEventListener('click', _findPathsFromOwned);
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

  async function _findPathsFromOwned() {
    if (!currentScanId) return;
    const results = document.getElementById('path-results');
    results.innerHTML = '<p style="color:#999; font-size:12px;">Finding paths from owned nodes…</p>';
    try {
      const data = await API.getPathsFromOwned(currentScanId);
      if (!data.owned_nodes?.length) {
        results.innerHTML = '<p style="color:#999; font-size:12px;">No owned nodes marked yet. Mark a node as Owned in the detail panel first.</p>';
        return;
      }
      _renderPathResults(data.paths || []);
    } catch (e) {
      results.innerHTML = `<p style="color:#F44336; font-size:12px;">Error: ${e.message}</p>`;
    }
  }

  function _renderPathResults(paths) {
    const results = document.getElementById('path-results');
    _hidePathChain();
    if (!paths.length) {
      results.innerHTML = '<p style="color:#999; font-size:12px; margin-top:8px;">No paths found.</p>';
      return;
    }
    results.innerHTML = paths.slice(0, 20).map((p, i) => {
      const steps = _pathSteps(p);
      const src = p.source_name || steps[0]?.display_name || steps[0]?.name || p.source || '';
      const tgt = p.target_name || steps[steps.length - 1]?.display_name || steps[steps.length - 1]?.name || (p.target || '').split('/').pop() || p.target || '';
      const hops = p.length ?? p.hops ?? (steps.length - 1);
      return `<div class="path-result-item" data-idx="${i}">
        <span class="path-hops">${hops} ${hops === 1 ? 'hop' : 'hops'}</span>
        <strong>${_esc(src)}</strong>
        <span style="color:#999;"> → </span>
        <span>${_esc(tgt)}</span>
      </div>`;
    }).join('');

    let _activeIdx = -1;
    results.querySelectorAll('.path-result-item').forEach((el, i) => {
      el.addEventListener('click', () => {
        results.querySelectorAll('.path-result-item').forEach(e => e.classList.remove('active'));
        if (_activeIdx === i) {
          _activeIdx = -1;
          _hidePathChain();
          return;
        }
        _activeIdx = i;
        el.classList.add('active');
        const p = paths[i];
        const steps = _pathSteps(p);
        const nodeIds = steps.map(s => s.node_id).filter(Boolean);
        GraphView.highlightPath(nodeIds);
        _showPathChain(p, steps);
        // Open detail panel for the TARGET node
        const targetStep = steps[steps.length - 1];
        if (targetStep?.node_id && currentScanId) {
          DetailPanel.show(currentScanId, targetStep.node_id);
        }
      });
    });
  }

  function _pathSteps(p) {
    const raw = p.path || [];
    if (!raw.length) return [];
    // If already step dicts (have node_id field), use them; otherwise treat as bare IDs
    if (typeof raw[0] === 'object' && raw[0].node_id) return raw;
    return raw.map(id => ({ node_id: id, name: id, display_name: id, node_type: '' }));
  }

  function _showPathChain(p, steps) {
    const container = document.getElementById('path-chain-detail');
    const title = document.getElementById('path-chain-title');
    const body = document.getElementById('path-chain-body');
    if (!container) return;

    const src = p.source_name || steps[0]?.display_name || steps[0]?.name || '';
    const tgt = p.target_name || steps[steps.length - 1]?.display_name || steps[steps.length - 1]?.name || (p.target || '').split('/').pop() || p.target || '';
    title.textContent = `${src} → ${tgt}`;

    body.innerHTML = steps.map((step, i) => {
      const isLast = i === steps.length - 1;
      const label = _esc(step.display_name || step.name || step.node_id || '');
      const typeTag = step.node_type ? `<span class="chain-type-tag">${_esc(step.node_type.replace(/_/g, ' '))}</span>` : '';

      let edgeHtml = '';
      if (i > 0 && step.edge_type) {
        const edgeLabel = step.edge_type.replace(/_/g, ' ');
        const roleSuffix = step.edge_props?.role_name ? `: ${step.edge_props.role_name}` : '';
        edgeHtml = `<div class="chain-edge"><span class="chain-edge-arrow">↳</span><span class="chain-edge-label">${_esc(edgeLabel + roleSuffix)}</span></div>`;
      }

      return `${i > 0 ? edgeHtml : ''}
        <div class="chain-node ${isLast ? 'chain-node-last' : ''}">
          <div class="chain-node-dot"></div>
          <div class="chain-node-info">
            <span class="chain-node-name">${label}</span>
            ${typeTag}
          </div>
        </div>`;
    }).join('');

    container.style.display = '';

    document.getElementById('path-chain-close')?.addEventListener('click', () => {
      _hidePathChain();
      document.querySelectorAll('#path-results .path-result-item').forEach(e => e.classList.remove('active'));
    }, { once: true });
  }

  function _hidePathChain() {
    const container = document.getElementById('path-chain-detail');
    if (container) container.style.display = 'none';
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
    const selA = document.getElementById('diff-scan-a');
    const selB = document.getElementById('diff-scan-b');
    document.getElementById('diff-results').innerHTML = '';

    if (!currentScanId) return;
    try {
      const scan = await API.getScan(currentScanId);
      const snapshots = await API.listSnapshots(scan.subscription_id);
      const opts = snapshots.map(s =>
        `<option value="${s.scan_id}">${_esc(s.snapshot_label || s.scan_id.substring(0,8))} — ${_fmtDate(s.completed_at)}</option>`
      ).join('');
      selA.innerHTML = '<option value="">Select baseline…</option>' + opts;
      selB.innerHTML = '<option value="">Select current…</option>' + opts;
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

  // ── Progress ──────────────────────────────
  function _showProgress(visible, pct = 0, msg = '', phase = '') {
    const overlay = document.getElementById('progress-overlay');
    const bar = document.getElementById('top-progress-bar');

    if (visible) {
      const rounded = Math.round(pct);
      if (overlay) {
        document.getElementById('progress-phase-label').textContent = phase || 'scanning';
        document.getElementById('progress-pct').textContent = `${rounded}%`;
        document.getElementById('progress-bar-fill').style.width = `${Math.max(pct, 2)}%`;
        document.getElementById('progress-msg').textContent = msg;
        overlay.classList.add('visible');
      }
      if (bar) {
        bar.classList.add('visible');
        bar.style.width = `${Math.max(pct, 2)}%`;
      }
      _setStatus('running', `${phase} — ${msg}`);
    } else {
      if (overlay) {
        document.getElementById('progress-pct').textContent = '100%';
        document.getElementById('progress-bar-fill').style.width = '100%';
        setTimeout(() => overlay.classList.remove('visible'), 450);
      }
      if (bar) {
        bar.style.width = '100%';
        setTimeout(() => {
          bar.classList.remove('visible');
          setTimeout(() => { bar.style.width = '0%'; }, 220);
        }, 450);
      }
    }
  }

  function _showWelcome(visible) {
    const el = document.getElementById('welcome');
    if (el) el.style.display = visible ? '' : 'none';
    // Hide owned section on welcome screen; shown again when a scan loads
    if (visible) {
      const owned = document.getElementById('owned-section');
      if (owned) owned.style.display = 'none';
    }
  }

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

  async function _editSnapshotLabel(scanId, currentLabel) {
    const newLabel = prompt('Snapshot label:', currentLabel || '');
    if (newLabel === null) return;
    await API.setSnapshotLabel(scanId, newLabel.trim() || scanId.substring(0, 8));
    await _loadScanList();
  }

  function _fmtDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function _esc(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  return { init, switchView, refreshOwnedList };
})();


// ── Detail Panel ────────────────────────────────────────────────────────────
const DetailPanel = (() => {
  let _scanId = null;
  let _nodeId = null;
  let _navStack = [];  // [{scanId, nodeId}]

  function show(scanId, nodeId, addToHistory = true) {
    if (addToHistory && _nodeId) {
      _navStack.push({ scanId: _scanId, nodeId: _nodeId });
    }
    _scanId = scanId;
    _nodeId = nodeId;

    API.getNodeDetail(scanId, nodeId).then(node => {
      document.getElementById('detail-title').textContent = node.display_name || node.name;
      document.getElementById('detail-type').textContent = node.node_type.replace(/_/g, ' ')
        + (node.is_owned ? ' · ♦ Owned' : '');

      const body = document.getElementById('detail-body');
      body.innerHTML = _render(node, scanId);
      document.getElementById('detail-panel').classList.add('open');

      // Update back button
      _updateBackBtn();

      // Bind owned toggle
      const ownedBtn = body.querySelector('#btn-toggle-owned');
      if (ownedBtn) {
        let _ownedProcessing = false;
        ownedBtn.addEventListener('click', async () => {
          if (_ownedProcessing) return;
          _ownedProcessing = true;
          const newState = !node.is_owned;
          try {
            await API.setNodeOwned(scanId, nodeId, newState);
            node.is_owned = newState;
            ownedBtn.textContent = newState ? 'Unmark Owned' : 'Mark as Owned';
            ownedBtn.style.background = newState ? '#FEF3C7' : '';
            ownedBtn.style.borderColor = newState ? '#F59E0B' : '';
            ownedBtn.style.color = newState ? '#B45309' : '';
            document.getElementById('detail-type').textContent =
              node.node_type.replace(/_/g, ' ') + (newState ? ' · ♦ Owned' : '');
            GraphView.updateNodeOwned(nodeId, newState);
            App.refreshOwnedList();
          } catch (e) {
            alert('Error: ' + e.message);
          } finally {
            _ownedProcessing = false;
          }
        });
      }

      // Navigate to related node on click
      body.querySelectorAll('.rel-item[data-nodeid]').forEach(el => {
        el.addEventListener('click', () => {
          GraphView.highlightNode(el.dataset.nodeid);
          show(scanId, el.dataset.nodeid, true);
        });
      });

      // Load attack paths async
      _loadNodePaths(scanId, nodeId);
    }).catch(console.error);
  }

  function _updateBackBtn() {
    const btn = document.getElementById('detail-back');
    if (!btn) return;
    btn.style.display = _navStack.length > 0 ? '' : 'none';
  }

  function goBack() {
    if (!_navStack.length) return;
    const prev = _navStack.pop();
    show(prev.scanId, prev.nodeId, false);
  }

  function close() {
    document.getElementById('detail-panel').classList.remove('open');
    _navStack = [];
    _nodeId = null;
    _scanId = null;
  }

  async function _loadNodePaths(scanId, nodeId) {
    const container = document.getElementById('detail-paths-section');
    if (!container) return;
    container.innerHTML = '<p style="color:#999; font-size:11px;">Loading paths…</p>';
    try {
      const data = await API.getAttackPaths(scanId, { from_node: nodeId, max_depth: 3 });
      const paths = data.paths || [];
      if (!paths.length) {
        container.innerHTML = '<p style="color:#bbb; font-size:11px;">No outbound attack paths found.</p>';
        return;
      }
      container.innerHTML = paths.slice(0, 5).map((p, i) => {
        const steps = _pathSteps(p);
        const tgt = p.target_name || steps[steps.length - 1]?.display_name || steps[steps.length - 1]?.name || (p.target || '').split('/').pop() || p.target || '';
        const hops = p.length ?? p.hops ?? (steps.length - 1);
        return `<div class="path-result-item" data-pidx="${i}" style="margin-bottom:4px;">
          <span class="path-hops">${hops}h</span>
          <span style="font-size:11px;">${_esc(tgt)}</span>
        </div>`;
      }).join('');

      let _activeIdx = -1;
      container.querySelectorAll('.path-result-item').forEach((el, i) => {
        el.addEventListener('click', () => {
          container.querySelectorAll('.path-result-item').forEach(e => e.classList.remove('active'));
          if (_activeIdx === i) {
            _activeIdx = -1;
            _hidePathChain();
            return;
          }
          _activeIdx = i;
          el.classList.add('active');
          const p = paths[i];
          const steps = _pathSteps(p);
          GraphView.highlightPath(steps.map(s => s.node_id).filter(Boolean));
          // Open attack path panel and show chain there
          document.getElementById('attack-path-panel')?.classList.add('visible');
          _showPathChain(p, steps);
        });
      });
    } catch (_) {
      container.innerHTML = '';
    }
  }

  function _render(node, scanId) {
    const riskColor = { critical: '#F44336', risky: '#FF9800', safe: '#4CAF50' }[node.risk_level] || '#9E9E9E';
    const props = node.properties || {};
    const isOwned = node.is_owned;

    let html = `
      <div style="display:flex; gap:8px; align-items:center; margin-bottom:12px;">
        <button id="btn-toggle-owned" class="btn btn-ghost" style="font-size:11px; padding:4px 10px;
          ${isOwned ? 'background:#FEF3C7; border-color:#F59E0B; color:#B45309;' : ''}">
          ${isOwned ? 'Unmark Owned' : 'Mark as Owned'}
        </button>
      </div>

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

    html += `<div class="detail-section">
      <div class="detail-section-title">Attack Paths From Here</div>
      <div id="detail-paths-section" style="min-height:20px;"></div>
    </div>`;

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

  return { show, close, goBack };
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
document.addEventListener('DOMContentLoaded', () => {
  App.init().catch(e => console.error('az-map init error:', e));
});

document.getElementById('detail-close')?.addEventListener('click', () => DetailPanel.close());
document.getElementById('detail-back')?.addEventListener('click', () => DetailPanel.goBack());
