/**
 * Graph view — Cytoscape.js with Obsidian-style force layout.
 *
 * Performance contract
 * --------------------
 * - cy.batch() wraps every operation that touches >1 element so Cytoscape
 *   fires a single redraw instead of N individual redraws.
 * - Layout is NEVER animated (animation drives per-frame callbacks that block
 *   the main thread).  numIter is capped by node count.
 * - Layout is skipped entirely when the graph canvas is not the active view;
 *   it runs on demand when the user switches to the Graph tab.
 * - A serial-load counter lets callers detect stale (superseded) loads and
 *   discard their results before touching the DOM.
 */
const GraphView = (() => {
  let cy = null;
  let currentScanId = null;
  let _layoutPending = false;   // true when elements loaded but layout not yet run
  let _loadSerial = 0;          // incremented on every load(); stale calls bail out

  const EDGE_COLORS = {
    has_role: '#18181B',
    member_of: '#0891B2',
    contains: '#94A3B8',
    assigned_to: '#EA580C',
    has_system_identity: '#7C3AED',
    can_escalate_to: '#DC2626',
    has_entra_role: '#B45309',
    default: '#D1D5DB',
  };

  function init() {
    cy = cytoscape({
      container: document.getElementById('cy'),
      elements: [],
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'label': 'data(nodeLabel)',
            'color': '#1a1a1a',
            'font-size': '10px',
            'font-family': '-apple-system, BlinkMacSystemFont, Inter, Segoe UI, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': '4px',
            'text-max-width': '90px',
            'text-wrap': 'ellipsis',
            'width': '32px',
            'height': '32px',
            'border-width': 'data(borderWidth)',
            'border-color': 'data(borderColor)',
            'shape': 'data(shape)',
            'overlay-opacity': 0,
            // No CSS transitions — they force style recalculations on every frame
          }
        },
        { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#18181B', 'z-index': 10 } },
        { selector: 'node.highlighted', style: { 'opacity': 1, 'z-index': 9 } },
        { selector: 'node.faded',       style: { 'opacity': 0.15 } },
        {
          selector: 'node.owned',
          style: { 'border-color': '#F59E0B', 'border-width': 4, 'overlay-color': '#F59E0B', 'overlay-padding': 5, 'overlay-opacity': 0.12 }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color':          (ele) => EDGE_COLORS[ele.data('edgeType')] || EDGE_COLORS.default,
            'target-arrow-color':  (ele) => EDGE_COLORS[ele.data('edgeType')] || EDGE_COLORS.default,
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.6,
            'label': '',
            'font-size': '9px',
            'color': '#666',
            'text-background-color': '#fff',
            'text-background-opacity': 1,
            'text-background-padding': '2px',
            'overlay-opacity': 0,
          }
        },
        { selector: 'edge:selected',    style: { 'opacity': 1, 'width': 2.5 } },
        { selector: 'edge.highlighted', style: { 'opacity': 1, 'width': 2 } },
        { selector: 'edge.faded',       style: { 'opacity': 0.04 } },
        { selector: 'node[riskLevel = "critical"]', style: { 'border-width': 3, 'border-color': '#F44336' } },
        { selector: 'node[riskLevel = "risky"]',    style: { 'border-width': 2, 'border-color': '#FF9800' } },
      ],
      layout: { name: 'preset' },
      minZoom: 0.1,
      maxZoom: 4,
      // Throttle rendering: skip frames when updates are cheap
      styleEnabled: true,
      hideEdgesOnViewport: true,   // skip edge rendering during pan/zoom
      textureOnViewport: true,     // use texture during motion (lower GPU pressure)
      motionBlur: false,
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      DetailPanel.show(currentScanId, node.id());
      _highlightNeighborhood(node);
    });

    cy.on('tap', 'edge', (evt) => {
      const edge = evt.target;
      const props = edge.data('properties') || {};
      const msg = [
        `Type: ${edge.data('edgeType')}`,
        props.role_name ? `Role: ${props.role_name}` : null,
        props.scope ? `Scope: ${_shortenScope(props.scope)}` : null,
      ].filter(Boolean).join('\n');
      const rect = cy.container().getBoundingClientRect();
      Tooltip.show(msg, evt.renderedPosition.x + rect.left, evt.renderedPosition.y + rect.top);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        _clearHighlight();
        DetailPanel.close();
        Tooltip.hide();
      }
    });

    cy.on('mouseover', 'node', (evt) => {
      const d = evt.target.data();
      const ownedTag = d.isOwned ? '\n♦ Owned' : '';
      Tooltip.show(
        `${d.fullLabel || d.nodeLabel}\n${d.nodeType}${d.riskLevel !== 'safe' ? '\n⚠ ' + d.riskLevel : ''}${ownedTag}`,
        evt.originalEvent.clientX + 12,
        evt.originalEvent.clientY - 10,
      );
    });
    cy.on('mouseout', 'node', () => Tooltip.hide());
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  function _isVisible() {
    return document.getElementById('graph-view')?.classList.contains('active') ?? false;
  }

  function _highlightNeighborhood(node) {
    const nbhd = node.closedNeighborhood();
    cy.batch(() => {
      cy.elements().addClass('faded');
      nbhd.removeClass('faded').addClass('highlighted');
      nbhd.edges().addClass('highlighted');
    });
  }

  function _clearHighlight() {
    cy.batch(() => cy.elements().removeClass('faded highlighted'));
  }

  function _shortenScope(scope) {
    const parts = scope.split('/');
    return parts.length > 5 ? '…/' + parts.slice(-2).join('/') : scope;
  }

  /**
   * Choose a layout strategy based on node count.
   *
   * animate is always false — animation drives requestAnimationFrame callbacks
   * that run on the main thread and cause "page unresponsive" for larger graphs.
   * numIter is capped to prevent >200 ms layouts.
   */
  function _runLayout() {
    if (!cy) return;
    const count = cy.nodes().length;
    if (count === 0) { _layoutPending = false; return; }

    // If the graph view isn't visible, defer the layout until switchToGraph()
    if (!_isVisible()) { _layoutPending = true; return; }
    _layoutPending = false;

    let cfg;
    if (count <= 60) {
      cfg = {
        name: 'cose', animate: false, fit: true, padding: 40,
        randomize: false, componentSpacing: 80,
        nodeRepulsion: () => 450000, edgeElasticity: () => 100,
        idealEdgeLength: 120, nodeOverlap: 20,
        numIter: 400, gravity: 80, nestingFactor: 5,
        initialTemp: 200, coolingFactor: 0.95, minTemp: 1.0,
      };
    } else if (count <= 250) {
      cfg = {
        name: 'cose', animate: false, fit: true, padding: 40,
        randomize: true, nodeRepulsion: () => 350000,
        idealEdgeLength: 90, numIter: 150,
      };
    } else if (count <= 800) {
      // For large graphs use a very cheap scatter — visually acceptable,
      // avoids seconds of blocking computation.
      cfg = {
        name: 'cose', animate: false, fit: true, padding: 40,
        randomize: true, nodeRepulsion: () => 200000,
        idealEdgeLength: 60, numIter: 60,
      };
    } else {
      // >800 nodes: just fit; the cose algorithm would freeze the browser.
      cy.fit(undefined, 40);
      return;
    }

    cy.layout(cfg).run();
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Load graph elements for a scan.  Returns stats.
   * Increments a serial number so concurrent calls from rapid scan-switching
   * don't clobber each other — only the latest call commits to the DOM.
   */
  async function load(scanId, filters = {}) {
    currentScanId = scanId;
    const serial = ++_loadSerial;

    const data = await API.getGraphElements(scanId, filters);
    if (serial !== _loadSerial) return data.stats; // superseded — discard

    const elements = [
      ...(data.elements.nodes || []),
      ...(data.elements.edges || []),
    ];

    if (!cy) init();

    // cy.batch() groups all mutations into a single synchronous redraw pass
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
      // Restore owned CSS class from data flag set by the backend
      cy.nodes().filter(n => n.data('isOwned')).addClass('owned');
    });

    _runLayout();
    return data.stats;
  }

  /** Called by switchView when the user navigates to the Graph tab. */
  function runLayoutIfNeeded() {
    if (_layoutPending) _runLayout();
  }

  function fitView() { cy && cy.fit(undefined, 40); }

  function zoomIn() {
    cy && cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function zoomOut() {
    cy && cy.zoom({ level: cy.zoom() * 0.75, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function resetLayout() {
    _layoutPending = false; // force re-run even if not pending
    _runLayout();
  }

  function highlightNode(nodeId) {
    if (!cy) return;
    const node = cy.getElementById(nodeId);
    if (node.length) {
      _clearHighlight();
      _highlightNeighborhood(node);
      cy.animate({ center: { eles: node }, zoom: 1.5, duration: 300 });
    }
  }

  function toggleEdgeLabels(show) {
    if (!cy) return;
    cy.batch(() => {
      cy.edges().style('label', show ? ele => ele.data('edgeLabel') || '' : '');
    });
  }

  function highlightPath(nodeIds) {
    if (!cy || !nodeIds || nodeIds.length < 2) return;

    const pathSet = new Set(nodeIds);

    // Collect path edges before entering batch so selector queries run outside the lock
    const pathEdges = cy.collection();
    for (let i = 0; i < nodeIds.length - 1; i++) {
      pathEdges.merge(cy.edges(`[source = "${nodeIds[i]}"][target = "${nodeIds[i + 1]}"]`));
    }
    const pathNodes = cy.nodes().filter(n => pathSet.has(n.id()));

    cy.batch(() => {
      cy.elements().removeClass('faded highlighted');
      cy.elements().addClass('faded');
      pathNodes.removeClass('faded').addClass('highlighted');
      pathEdges.removeClass('faded').addClass('highlighted');
      // Label highlighted edges (batch-safe: style() inside batch is fine)
      pathEdges.forEach(e => e.style('label', e.data('edgeLabel') || ''));
    });

    if (pathNodes.length) {
      cy.animate({ fit: { eles: pathNodes, padding: 80 }, duration: 400 });
    }
  }

  function markOwnedNodes(nodeIds) {
    if (!cy) return;
    cy.batch(() => {
      nodeIds.forEach(nid => {
        const n = cy.getElementById(nid);
        if (n.length) { n.addClass('owned'); n.data('isOwned', true); }
      });
    });
  }

  function updateNodeOwned(nodeId, owned) {
    if (!cy) return;
    const n = cy.getElementById(nodeId);
    if (!n.length) return;
    cy.batch(() => {
      n.data('isOwned', owned);
      if (owned) {
        n.addClass('owned');
      } else {
        n.removeClass('owned');
        const rl = n.data('riskLevel') || 'safe';
        n.data('borderColor', { critical: '#F44336', risky: '#FF9800', safe: '#9E9E9E' }[rl] || '#9E9E9E');
        n.data('borderWidth', { critical: 3, risky: 2, safe: 1 }[rl] || 1);
      }
    });
  }

  function applyDiffOverlay(delta) {
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().forEach(n => {
        const id = n.id();
        if      (delta.new.has(id))     n.style({ 'border-color': '#4CAF50', 'border-width': 4 });
        else if (delta.removed.has(id)) n.style({ 'border-color': '#F44336', 'border-width': 4, 'opacity': 0.5 });
        else if (delta.riskUp.has(id))  n.style({ 'border-color': '#FF9800', 'border-width': 4 });
        else if (delta.riskDown.has(id))n.style({ 'border-color': '#2196F3', 'border-width': 3 });
      });
    });
  }

  function clearDiffOverlay() {
    if (!cy) return;
    const bc = { critical: '#F44336', risky: '#FF9800', safe: '#9E9E9E' };
    const bw = { critical: 3, risky: 2, safe: 1 };
    cy.batch(() => {
      cy.nodes().forEach(n => {
        const rl = n.data('riskLevel') || 'safe';
        n.style({
          'border-color': n.data('isOwned') ? '#F59E0B' : (bc[rl] || '#9E9E9E'),
          'border-width': n.data('isOwned') ? 4 : (bw[rl] || 1),
          'opacity': 1,
        });
      });
    });
  }

  return {
    init, load, runLayoutIfNeeded,
    fitView, zoomIn, zoomOut, resetLayout, highlightNode,
    toggleEdgeLabels, highlightPath,
    markOwnedNodes, updateNodeOwned,
    applyDiffOverlay, clearDiffOverlay,
  };
})();
