/**
 * Dashboard view — risk summary, severity donut, node breakdown, top findings.
 * Uses plain SVG — no D3 or chart library needed.
 */
const DashboardView = (() => {
  let currentScanId = null;

  async function render(scanId) {
    currentScanId = scanId;
    const container = document.getElementById('dashboard-content');
    container.innerHTML = '<p style="color:#999; padding:20px;">Loading dashboard…</p>';

    try {
      const [stats, summary] = await Promise.all([
        API.getGraphStats(scanId),
        API.getFindingsSummary(scanId),
      ]);
      container.innerHTML = _buildHTML(stats, summary);
      _bindFindingClicks(container, scanId);
    } catch (e) {
      container.innerHTML = `<p style="color:#F44336; padding:20px;">Error: ${e.message}</p>`;
    }
  }

  function _buildHTML(stats, summary) {
    const bySev  = summary.by_severity  || {};
    const byType = summary.by_type      || {};
    const topRisk = summary.top_risk    || [];
    const nc = stats.node_counts        || {};
    const fc = stats.finding_counts     || {};

    const totalFindings = Object.values(fc).reduce((a, b) => a + b, 0);
    const totalNodes    = stats.total_role_assignments !== undefined
      ? Object.values(nc).reduce((a, b) => a + b, 0)
      : 0;
    const totalRAs = stats.total_role_assignments || 0;

    const scanDate = stats.completed_at
      ? new Date(stats.completed_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
      : (stats.started_at ? new Date(stats.started_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

    const metaHtml = `
    <div class="dash-meta-bar">
      ${stats.snapshot_label ? `<span class="dash-meta-item"><strong>Snapshot:</strong> ${_esc(stats.snapshot_label)}</span>` : ''}
      <span class="dash-meta-item"><strong>Subscription:</strong> ${_esc(stats.subscription_name || stats.subscription_id || '—')}</span>
      ${stats.tenant_id ? `<span class="dash-meta-item"><strong>Tenant:</strong> ${_esc(stats.tenant_id)}</span>` : ''}
      <span class="dash-meta-item"><strong>Scanned:</strong> ${scanDate}</span>
      <span class="dash-meta-item"><strong>Status:</strong> ${_esc(stats.status || '—')}</span>
    </div>`;

    return `
    <div class="dash-grid">

      ${metaHtml}

      <!-- ── Stat cards ── -->
      <div class="dash-row">
        ${_statCard('Total Resources', Object.values(nc).reduce((a,b)=>a+b,0), '#2196F3')}
        ${_statCard('Role Assignments', totalRAs, '#7B68EE')}
        ${_statCard('Total Findings', totalFindings, '#FF9800')}
        ${_statCard('Critical Findings', fc.critical || 0, '#F44336')}
      </div>

      <!-- ── Severity donut + findings by type ── -->
      <div class="dash-row" style="align-items:flex-start; gap:20px;">
        <div class="dash-card" style="flex:1; min-width:260px;">
          <div class="dash-card-title">Findings by Severity</div>
          ${_donutChart(bySev)}
        </div>
        <div class="dash-card" style="flex:1; min-width:200px;">
          <div class="dash-card-title">Findings by Type</div>
          ${_barChart(byType, '#7B68EE')}
        </div>
        <div class="dash-card" style="flex:1; min-width:200px;">
          <div class="dash-card-title">Resources by Type</div>
          ${_barChart(nc, '#2196F3')}
        </div>
      </div>

      <!-- ── Top-5 findings ── -->
      <div class="dash-card" style="margin-top:0;">
        <div class="dash-card-title">Top Risk Findings</div>
        <div id="dash-top-findings">
          ${topRisk.length === 0
            ? '<p style="color:#999; font-size:13px;">No findings yet.</p>'
            : topRisk.map(f => _findingCard(f)).join('')}
        </div>
      </div>

    </div>`;
  }

  function _statCard(label, value, color) {
    return `
    <div class="dash-stat-card">
      <div class="dash-stat-value" style="color:${color};">${value}</div>
      <div class="dash-stat-label">${label}</div>
    </div>`;
  }

  function _donutChart(bySev) {
    const SEV = [
      { key: 'critical', color: '#F44336', label: 'Critical' },
      { key: 'high',     color: '#FF9800', label: 'High'     },
      { key: 'medium',   color: '#FFC107', label: 'Medium'   },
      { key: 'low',      color: '#4CAF50', label: 'Low'      },
      { key: 'info',     color: '#9E9E9E', label: 'Info'     },
    ];
    const data = SEV.map(s => ({ ...s, count: bySev[s.key] || 0 })).filter(s => s.count > 0);
    const total = data.reduce((a, d) => a + d.count, 0);

    if (total === 0) return '<p style="color:#999; font-size:13px; padding:12px 0;">No findings.</p>';

    const R = 70, r = 42, cx = 90, cy = 90;
    let segments = '';
    let angle = -Math.PI / 2;
    for (const d of data) {
      const sweep = (d.count / total) * 2 * Math.PI;
      const x1 = cx + R * Math.cos(angle);
      const y1 = cy + R * Math.sin(angle);
      const x2 = cx + R * Math.cos(angle + sweep);
      const y2 = cy + R * Math.sin(angle + sweep);
      const x3 = cx + r * Math.cos(angle + sweep);
      const y3 = cy + r * Math.sin(angle + sweep);
      const x4 = cx + r * Math.cos(angle);
      const y4 = cy + r * Math.sin(angle);
      const large = sweep > Math.PI ? 1 : 0;
      segments += `<path d="M${x1},${y1} A${R},${R} 0 ${large},1 ${x2},${y2} L${x3},${y3} A${r},${r} 0 ${large},0 ${x4},${y4} Z"
        fill="${d.color}" opacity="0.9"/>`;
      angle += sweep;
    }
    const legend = data.map(d => `
      <div style="display:flex; align-items:center; gap:6px; font-size:12px; margin:3px 0;">
        <div style="width:10px; height:10px; border-radius:50%; background:${d.color}; flex-shrink:0;"></div>
        <span style="color:#555;">${d.label}</span>
        <span style="margin-left:auto; font-weight:600; color:#333;">${d.count}</span>
      </div>`).join('');

    return `<div style="display:flex; align-items:center; gap:20px; flex-wrap:wrap;">
      <svg width="180" height="180" viewBox="0 0 180 180">
        ${segments}
        <text x="${cx}" y="${cy+5}" text-anchor="middle" font-size="18" font-weight="700" fill="#333">${total}</text>
        <text x="${cx}" y="${cy+20}" text-anchor="middle" font-size="10" fill="#999">total</text>
      </svg>
      <div style="flex:1; min-width:100px;">${legend}</div>
    </div>`;
  }

  function _barChart(counts, color) {
    const entries = Object.entries(counts)
      .filter(([, v]) => v > 0)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8);
    if (entries.length === 0) return '<p style="color:#999; font-size:13px; padding:8px 0;">No data.</p>';
    const max = Math.max(...entries.map(([, v]) => v));
    return entries.map(([key, val]) => `
      <div style="margin: 5px 0;">
        <div style="display:flex; justify-content:space-between; font-size:11px; color:#666; margin-bottom:2px;">
          <span>${key.replace(/_/g,' ')}</span><span style="font-weight:600; color:#333;">${val}</span>
        </div>
        <div style="height:6px; background:#f0f0f0; border-radius:3px; overflow:hidden;">
          <div style="height:100%; width:${(val/max)*100}%; background:${color}; border-radius:3px; opacity:0.8;"></div>
        </div>
      </div>`).join('');
  }

  function _findingCard(f) {
    const SEV_COLOR = { critical: '#F44336', high: '#FF9800', medium: '#FFC107', low: '#4CAF50', info: '#9E9E9E' };
    const color = SEV_COLOR[f.severity] || '#9E9E9E';
    return `
    <div class="dash-finding-card" data-finding-id="${f.id}" data-node-id="${f.affected_node_id || ''}">
      <div style="display:flex; align-items:center; gap:10px;">
        <div style="width:4px; height:40px; background:${color}; border-radius:2px; flex-shrink:0;"></div>
        <div style="flex:1; min-width:0;">
          <div style="font-weight:500; font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${_esc(f.title)}</div>
          <div style="font-size:11px; color:#999; margin-top:2px;">${_esc(f.affected_node_name || '')} · risk score ${f.risk_score}</div>
        </div>
        <span class="severity-badge ${f.severity}" style="flex-shrink:0;">${f.severity}</span>
      </div>
    </div>`;
  }

  function _bindFindingClicks(container, scanId) {
    container.querySelectorAll('.dash-finding-card').forEach(card => {
      card.addEventListener('click', () => {
        const nodeId = card.dataset.nodeId;
        if (nodeId) {
          App.switchView('graph');
          setTimeout(() => {
            GraphView.highlightNode(nodeId);
            DetailPanel.show(scanId, nodeId);
          }, 100);
        }
      });
    });
  }

  function _esc(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  return { render };
})();
