/**
 * Table view — findings, inventory, role assignments.
 */
const TableView = (() => {
  let currentScanId = null;
  let currentTab = 'findings';

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function init() {
    document.querySelectorAll('.table-tab').forEach(t => {
      t.addEventListener('click', () => switchTab(t.dataset.tab));
    });
  }

  function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.table-tab').forEach(t =>
      t.classList.toggle('active', t.dataset.tab === tab)
    );
    if (currentScanId) render(currentScanId);
  }

  async function render(scanId) {
    currentScanId = scanId;
    const container = document.getElementById('table-content');
    container.innerHTML = '<p style="color:#999; padding:20px;">Loading…</p>';

    try {
      if (currentTab === 'findings') {
        await _renderFindings(container, scanId);
      } else if (currentTab === 'inventory') {
        await _renderInventory(container, scanId);
      } else if (currentTab === 'roles') {
        await _renderRoles(container, scanId);
      }
    } catch (e) {
      container.innerHTML = `<p style="color:#F44336; padding:20px;">Error: ${e.message}</p>`;
    }
  }

  async function _renderFindings(container, scanId) {
    const data = await API.getFindings(scanId, { limit: 500 });
    const findings = data.findings || [];

    if (findings.length === 0) {
      container.innerHTML = '<p style="color:#999; padding:20px;">No findings.</p>';
      return;
    }

    const html = `
      <table class="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Risk</th>
            <th>Title</th>
            <th>Type</th>
            <th>Affected Resource</th>
            <th>Blast Radius</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map(f => `
          <tr class="finding-row" data-id="${f.id}" data-node-id="${f.affected_node_id || ''}" style="cursor:pointer;">
            <td><span class="severity-badge ${f.severity}">${f.severity}</span></td>
            <td>
              <div class="risk-bar-wrap">
                <div class="risk-bar"><div class="risk-bar-fill" style="width:${f.risk_score * 10}%; background:${_riskColor(f.risk_score)};"></div></div>
                <span style="font-size:11px; color:#666;">${f.risk_score}</span>
              </div>
            </td>
            <td style="max-width:260px;">
              <div style="font-weight:500;">${_esc(f.title)}</div>
              <div style="font-size:11px; color:#999; margin-top:2px;">${_esc((f.description || '').substring(0, 90))}${(f.description || '').length > 90 ? '…' : ''}</div>
            </td>
            <td>
              <span class="node-type-tag explain-trigger" data-finding-id="${f.id}"
                    style="cursor:pointer; border-bottom:1px dashed #ccc;"
                    title="Click to explain">
                ${f.finding_type.replace(/_/g, ' ')}
              </span>
            </td>
            <td style="font-size:12px;">
              ${f.affected_node_id
                ? `<span class="table-node-link" data-node-id="${f.affected_node_id}" style="color:var(--accent); cursor:pointer; text-decoration:underline;">${_esc(f.affected_node_name || '—')}</span>`
                : `<span style="color:#666;">${_esc(f.affected_node_name || '—')}</span>`}
            </td>
            <td style="font-size:12px; color:#666;">${f.blast_radius}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>`;
    container.innerHTML = html;

    // "View in graph" links on affected resource name
    container.querySelectorAll('.table-node-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.stopPropagation();
        const nodeId = link.dataset.nodeId;
        if (nodeId) {
          App.switchView('graph');
          setTimeout(() => {
            GraphView.highlightNode(nodeId);
            DetailPanel.show(currentScanId, nodeId);
          }, 100);
        }
      });
    });

    // Explain trigger: click finding_type tag → rich inline explainer
    container.querySelectorAll('.explain-trigger').forEach(tag => {
      tag.addEventListener('click', (e) => {
        e.stopPropagation();
        const fid = tag.dataset.findingId;
        const row = tag.closest('tr');
        // Toggle: remove if already shown
        const next = row.nextElementSibling;
        if (next && next.classList.contains('explain-row')) { next.remove(); return; }
        // Remove any other open explain rows
        container.querySelectorAll('.explain-row').forEach(r => r.remove());
        const f = findings.find(x => x.id === fid);
        if (!f) return;
        const chain = (f.attack_chain || []).map(s =>
          `<div class="explain-step"><span class="explain-step-num">${s.step}.</span><span>${_esc(s.action)}</span></div>`
        ).join('');
        const explainRow = document.createElement('tr');
        explainRow.className = 'explain-row';
        explainRow.innerHTML = `<td colspan="6">
          ${f.why_risky ? `<div class="explain-why">⚠ <strong>Why this is risky:</strong> ${_esc(f.why_risky)}</div>` : ''}
          ${chain ? `<div style="margin: 8px 0;"><strong style="font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:#999;">Attack Chain</strong>${chain}</div>` : ''}
          ${f.remediation ? `<div class="explain-remediation">✓ <strong>Remediation:</strong> ${_esc(f.remediation)}</div>` : ''}
        </td>`;
        row.after(explainRow);
      });
    });

    // Expandable rows — show attack chain + remediation on row click
    container.querySelectorAll('.finding-row').forEach(row => {
      row.addEventListener('click', () => {
        const existing = row.nextElementSibling;
        if (existing && existing.classList.contains('finding-detail-row')) {
          existing.remove();
          return;
        }
        const f = findings.find(x => x.id === row.dataset.id);
        if (!f) return;
        const det = document.createElement('tr');
        det.className = 'finding-detail-row';
        const chain = (f.attack_chain || []).map(s =>
          `<div class="chain-step"><span class="chain-num">${s.step}</span><span class="chain-text">${_esc(s.action)}</span></div>`
        ).join('');
        det.innerHTML = `<td colspan="6" style="background:#fafafa; padding:16px;">
          ${f.why_risky ? `<p style="font-size:13px; margin-bottom:10px;"><strong>Why risky:</strong> ${_esc(f.why_risky)}</p>` : ''}
          ${chain ? `<div style="margin-bottom:10px;">${chain}</div>` : ''}
          ${f.remediation ? `<p style="font-size:13px; color:#2E7D32;"><strong>Remediation:</strong> ${_esc(f.remediation)}</p>` : ''}
        </td>`;
        row.after(det);
      });
    });
  }

  let _inventoryOffset = 0;
  const _inventoryLimit = 200;

  async function _renderInventory(container, scanId, offset = 0) {
    _inventoryOffset = offset;
    if (offset === 0) {
      container.innerHTML = '<p style="color:#999; padding:20px;">Loading...</p>';
    }

    const data = await API.getInventory(scanId, { limit: _inventoryLimit, offset });
    const nodes = data.nodes || [];
    const total = data.total || 0;

    if (total === 0) {
      container.innerHTML = '<p style="color:#999; padding:20px;">No resources found.</p>';
      return;
    }

    const header = `<div style="padding:10px 16px; font-size:12px; color:#666; background:#f8f8f8; border-bottom:1px solid #eee;">
      Showing ${offset + 1}–${Math.min(offset + nodes.length, total)} of ${total.toLocaleString()} resources
      (sorted by risk score)
    </div>`;

    const rows = nodes.map(n => `
      <tr class="inventory-row" data-nodeid="${_esc(n.node_id)}" style="cursor:pointer;">
        <td style="font-weight:500;">${_esc(n.display_name || n.name)}</td>
        <td><span class="node-type-tag">${(n.node_type || '').replace(/_/g, ' ')}</span></td>
        <td><span class="severity-badge ${n.risk_level === 'safe' ? 'low' : n.risk_level}">${n.risk_level}</span></td>
        <td>
          <div class="risk-bar-wrap">
            <div class="risk-bar"><div class="risk-bar-fill" style="width:${(n.risk_score || 0) * 10}%; background:${_riskColor(n.risk_score)};"></div></div>
            <span style="font-size:11px; color:#666;">${n.risk_score}</span>
          </div>
        </td>
        <td style="font-size:12px; color:#666;">${(n.risk_reasons || []).slice(0, 2).join(', ') || '—'}</td>
      </tr>`).join('');

    const hasMore = offset + nodes.length < total;
    const pagination = hasMore
      ? `<div style="padding:12px 16px; text-align:center; border-top:1px solid #eee;">
           <button id="inv-load-more" class="btn btn-ghost" style="font-size:12px;">
             Load next ${_inventoryLimit} (${total - offset - nodes.length} remaining)
           </button>
         </div>`
      : '';

    container.innerHTML = header + `
      <table class="data-table">
        <thead>
          <tr><th>Name</th><th>Type</th><th>Risk Level</th><th>Risk Score</th><th>Risk Reasons</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>` + pagination;

    container.querySelectorAll('.inventory-row').forEach(row => {
      row.addEventListener('click', () => {
        const nodeId = row.dataset.nodeid;
        App.switchView('graph');
        setTimeout(() => {
          GraphView.highlightNode(nodeId);
          DetailPanel.show(scanId, nodeId);
        }, 100);
      });
    });

    document.getElementById('inv-load-more')?.addEventListener('click', () => {
      _renderInventory(container, scanId, offset + _inventoryLimit);
    });
  }

  async function _renderRoles(container, scanId) {
    // Fetch graph stats for role assignment counts
    const stats = await API.getGraphStats(scanId);
    const data = await API.getGraphElements(scanId, { node_types: 'role_definition' });
    const nodes = (data.elements.nodes || []).map(n => n.data);

    if (nodes.length === 0) {
      container.innerHTML = '<p style="color:#999; padding:20px;">No role data found.</p>';
      return;
    }

    const html = `
      <div style="margin-bottom:16px; padding:12px 16px; background:#f8f8f8; border-radius:6px;">
        <strong>Total Role Assignments:</strong> ${stats.total_role_assignments || 0} &nbsp;|&nbsp;
        <strong>Role Definitions:</strong> ${nodes.length}
      </div>
      <table class="data-table">
        <thead>
          <tr><th>Role Name</th><th>Built-in</th><th>Privilege Level</th></tr>
        </thead>
        <tbody>
          ${nodes.map(n => `
          <tr>
            <td style="font-weight:500;">${_esc(n.fullLabel || n.label)}</td>
            <td style="font-size:12px; color:#666;">${n.properties?.is_builtin ? 'Yes' : 'Custom'}</td>
            <td><span class="severity-badge ${_privLevel(n.properties?.privilege_level)}">${n.properties?.privilege_level || 'low'}</span></td>
          </tr>`).join('')}
        </tbody>
      </table>`;
    container.innerHTML = html;
  }

  function _riskColor(score) {
    if (score >= 7.5) return '#F44336';
    if (score >= 5.0) return '#FF9800';
    if (score >= 2.5) return '#FFC107';
    return '#4CAF50';
  }

  function _privLevel(level) {
    const map = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
    return map[level] || 'info';
  }

  function _esc(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  return { init, render, switchTab };
})();
