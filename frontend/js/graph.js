/**
 * Graph view — Cytoscape.js with Obsidian-style force layout.
 */
const GraphView = (() => {
  let cy = null;
  let currentScanId = null;

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
          selector: 'node.owned',
          style: {
            'border-color': '#F59E0B',
            'border-width': 4,
            'overlay-color': '#F59E0B',
            'overlay-padding': 5,
            'overlay-opacity': 0.12,
          }
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
            'label': '',
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
          style: { 'opacity': 1, 'width': 2 }
        },
        {
          selector: 'edge.faded',
          style: { 'opacity': 0.05 }
        },
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
      const ownedTag = d.isOwned ? '\n♦ Owned' : '';
      Tooltip.show(
        `${d.fullLabel || d.nodeLabel}\n${d.nodeType}${d.riskLevel !== 'safe' ? '\n⚠ ' + d.riskLevel : ''}${ownedTag}`,
        evt.originalEvent.clientX + 12,
        evt.originalEvent.clientY - 10,
      );
    });
    cy.on('mouseout', 'node', () => Tooltip.hide());
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
    // Re-apply owned class after load (backend already sets classes, but ensure it)
    cy.nodes().forEach(n => {
      if (n.data('isOwned')) n.addClass('owned');
    });
    _runLayout();
    return data.stats;
  }

  function markOwnedNodes(nodeIds) {
    if (!cy) return;
    nodeIds.forEach(nid => {
      const n = cy.getElementById(nid);
      if (n.length) {
        n.addClass('owned');
        n.data('isOwned', true);
      }
    });
  }

  function updateNodeOwned(nodeId, owned) {
    if (!cy) return;
    const n = cy.getElementById(nodeId);
    if (!n.length) return;
    n.data('isOwned', owned);
    if (owned) {
      n.addClass('owned');
    } else {
      n.removeClass('owned');
      const riskLevel = n.data('riskLevel') || 'safe';
      const borderColors = { critical: '#F44336', risky: '#FF9800', safe: '#9E9E9E' };
      const borderWidths = { critical: 3, risky: 2, safe: 1 };
      n.data('borderColor', borderColors[riskLevel] || '#9E9E9E');
      n.data('borderWidth', borderWidths[riskLevel] || 1);
    }
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

  function fitView() { cy && cy.fit(undefined, 40); }

  function zoomIn() {
    cy && cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function zoomOut() {
    cy && cy.zoom({ level: cy.zoom() * 0.75, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  function resetLayout() { _runLayout(); }

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
    cy.edges().style('label', show ? ele => ele.data('edgeLabel') || '' : '');
  }

  function highlightPath(nodeIds) {
    if (!cy || !nodeIds || nodeIds.length < 2) return;
    _clearHighlight();

    const pathSet = new Set(nodeIds);
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
    pathEdges.forEach(e => e.style('label', e.data('edgeLabel') || ''));

    const pathNodes = cy.nodes().filter(n => pathSet.has(n.id()));
    if (pathNodes.length) {
      cy.animate({ fit: { eles: pathNodes, padding: 80 }, duration: 500 });
    }
  }

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
        'border-color': n.data('isOwned') ? '#F59E0B' : (borderColors[riskLevel] || '#9E9E9E'),
        'border-width': n.data('isOwned') ? 4 : (borderWidths[riskLevel] || 1),
        'opacity': 1,
      });
    });
  }

  return { init, load, fitView, zoomIn, zoomOut, resetLayout, highlightNode,
           toggleEdgeLabels, highlightPath, applyDiffOverlay, clearDiffOverlay,
           markOwnedNodes, updateNodeOwned };
})();
