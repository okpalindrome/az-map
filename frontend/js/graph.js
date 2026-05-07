/**
 * Graph view — Cytoscape.js with Obsidian-style force layout.
 */
const GraphView = (() => {
  let cy = null;
  let currentScanId = null;
  let legendVisible = true;

  const EDGE_COLORS = {
    has_role: '#18181B',       // black — role assignment (most important edge type)
    member_of: '#0891B2',      // cyan-600 — group membership
    contains: '#94A3B8',       // slate-400 — structural containment
    assigned_to: '#EA580C',    // orange-600 — managed identity assignment
    has_system_identity: '#7C3AED', // violet — system identity
    can_escalate_to: '#DC2626', // red-600 — escalation path
    has_entra_role: '#B45309', // amber-700 — Entra directory role
    default: '#D1D5DB',        // gray-300
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
            'label': 'data(label)',
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
            'transition-property': 'background-color, border-color, opacity',
            'transition-duration': '0.15s',
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#18181B',
            'background-color': 'data(color)',
            'z-index': 10,
          }
        },
        {
          selector: 'node.highlighted',
          style: {
            'opacity': 1,
            'z-index': 9,
          }
        },
        {
          selector: 'node.faded',
          style: { 'opacity': 0.2 }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': (ele) => EDGE_COLORS[ele.data('edgeType')] || EDGE_COLORS.default,
            'target-arrow-color': (ele) => EDGE_COLORS[ele.data('edgeType')] || EDGE_COLORS.default,
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.6,
            'label': '',  // labels hidden by default for cleanliness
            'font-size': '9px',
            'color': '#666',
            'text-background-color': '#fff',
            'text-background-opacity': 1,
            'text-background-padding': '2px',
            'overlay-opacity': 0,
          }
        },
        {
          selector: 'edge:selected',
          style: { 'opacity': 1, 'width': 2.5 }
        },
        {
          selector: 'edge.highlighted',
          style: { 'opacity': 1, 'width': 2, 'label': 'data(label)' }
        },
        {
          selector: 'edge.faded',
          style: { 'opacity': 0.05 }
        },
        // Risk level rings
        {
          selector: 'node[riskLevel = "critical"]',
          style: {
            'border-width': 3,
            'border-color': '#F44336',
          }
        },
        {
          selector: 'node[riskLevel = "risky"]',
          style: {
            'border-width': 2,
            'border-color': '#FF9800',
          }
        },
      ],

      layout: { name: 'preset' },
      minZoom: 0.1,
      maxZoom: 4,
    });

    // Node click → show detail panel
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      DetailPanel.show(currentScanId, node.id());
      _highlightNeighborhood(node);
    });

    // Edge click → show edge detail in tooltip
    cy.on('tap', 'edge', (evt) => {
      const edge = evt.target;
      const props = edge.data('properties') || {};
      const msg = [
        `Type: ${edge.data('edgeType')}`,
        props.role_name ? `Role: ${props.role_name}` : null,
        props.scope ? `Scope: ${_shortenScope(props.scope)}` : null,
      ].filter(Boolean).join('\n');
      Tooltip.show(msg, evt.renderedPosition.x + cy.container().getBoundingClientRect().left,
                   evt.renderedPosition.y + cy.container().getBoundingClientRect().top);
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
      Tooltip.show(
        `${d.fullLabel || d.label}\n${d.nodeType}${d.riskLevel !== 'safe' ? '\n⚠ ' + d.riskLevel : ''}`,
        evt.originalEvent.clientX + 12,
        evt.originalEvent.clientY - 10,
      );
    });
    cy.on('mouseout', 'node', () => Tooltip.hide());
    cy.on('mouseover', 'edge', (evt) => {
      // handled on tap for edges
    });
  }

  function _highlightNeighborhood(node) {
    const neighborhood = node.closedNeighborhood();
    cy.elements().addClass('faded');
    neighborhood.removeClass('faded').addClass('highlighted');
    neighborhood.edges().addClass('highlighted');
  }

  function _clearHighlight() {
    cy.elements().removeClass('faded highlighted');
  }

  function _shortenScope(scope) {
    const parts = scope.split('/');
    return parts.length > 5 ? '…/' + parts.slice(-2).join('/') : scope;
  }

  async function load(scanId, filters = {}) {
    currentScanId = scanId;
    const data = await API.getGraphElements(scanId, filters);
    const elements = [
      ...(data.elements.nodes || []),
      ...(data.elements.edges || []),
    ];
    if (!cy) init();
    cy.elements().remove();
    cy.add(elements);
    _runLayout();
    return data.stats;
  }

  function _runLayout() {
    const count = cy.nodes().length;
    if (count === 0) return;

    let layoutConfig;
    if (count < 80) {
      layoutConfig = {
        name: 'cose',
        animate: true,
        animationDuration: 600,
        idealEdgeLength: 120,
        nodeOverlap: 20,
        refresh: 20,
        fit: true,
        padding: 40,
        randomize: false,
        componentSpacing: 80,
        nodeRepulsion: () => 450000,
        edgeElasticity: () => 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0,
      };
    } else {
      layoutConfig = {
        name: 'cose',
        animate: false,
        randomize: true,
        fit: true,
        padding: 40,
        nodeRepulsion: () => 400000,
        idealEdgeLength: 100,
        numIter: 500,
      };
    }

    cy.layout(layoutConfig).run();
  }

  function fitView() {
    cy && cy.fit(undefined, 40);
  }

  function zoomIn() {
    cy && cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function zoomOut() {
    cy && cy.zoom({ level: cy.zoom() * 0.75, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function resetLayout() {
    _runLayout();
  }

  function highlightNode(nodeId) {
    if (!cy) return;
    const node = cy.getElementById(nodeId);
    if (node.length) {
      _clearHighlight();
      _highlightNeighborhood(node);
      cy.animate({ center: { eles: node }, zoom: 1.5, duration: 400 });
    }
  }

  function toggleEdgeLabels(show) {
    if (!cy) return;
    cy.edges().style('label', show ? 'data(label)' : '');
  }

  /**
   * Highlight a specific attack path (list of node IDs).
   * Fades everything else, colors path nodes and edges distinctly.
   */
  function highlightPath(nodeIds) {
    if (!cy || !nodeIds || nodeIds.length < 2) return;
    _clearHighlight();

    const pathSet = new Set(nodeIds);
    // Collect path edges (edges between consecutive path nodes)
    const pathEdges = cy.collection();
    for (let i = 0; i < nodeIds.length - 1; i++) {
      const src = nodeIds[i], tgt = nodeIds[i + 1];
      const edge = cy.edges(`[source = "${src}"][target = "${tgt}"]`);
      pathEdges.merge(edge);
    }

    cy.elements().addClass('faded');
    nodeIds.forEach(nid => {
      const n = cy.getElementById(nid);
      if (n.length) n.removeClass('faded').addClass('highlighted');
    });
    pathEdges.removeClass('faded').addClass('highlighted');

    // Animate to fit path
    const pathNodes = cy.nodes().filter(n => pathSet.has(n.id()));
    if (pathNodes.length) {
      cy.animate({ fit: { eles: pathNodes, padding: 80 }, duration: 500 });
    }
  }

  /**
   * Apply diff overlay coloring to nodes.
   * delta: { new: Set<id>, removed: Set<id>, riskUp: Set<id>, riskDown: Set<id> }
   */
  function applyDiffOverlay(delta) {
    if (!cy) return;
    cy.nodes().forEach(n => {
      const id = n.id();
      if (delta.new.has(id)) {
        n.style({ 'border-color': '#4CAF50', 'border-width': 4 });
      } else if (delta.removed.has(id)) {
        n.style({ 'border-color': '#F44336', 'border-width': 4, 'opacity': 0.5 });
      } else if (delta.riskUp.has(id)) {
        n.style({ 'border-color': '#FF9800', 'border-width': 4 });
      } else if (delta.riskDown.has(id)) {
        n.style({ 'border-color': '#2196F3', 'border-width': 3 });
      }
    });
  }

  function clearDiffOverlay() {
    if (!cy) return;
    cy.nodes().forEach(n => {
      const riskLevel = n.data('riskLevel') || 'safe';
      const borderColors = { critical: '#F44336', risky: '#FF9800', safe: '#9E9E9E' };
      const borderWidths = { critical: 3, risky: 2, safe: 1 };
      n.style({
        'border-color': borderColors[riskLevel] || '#9E9E9E',
        'border-width': borderWidths[riskLevel] || 1,
        'opacity': 1,
      });
    });
  }

  return { init, load, fitView, zoomIn, zoomOut, resetLayout, highlightNode,
           toggleEdgeLabels, highlightPath, applyDiffOverlay, clearDiffOverlay };
})();
