// Path view: graph, hop table and connection cards for "Network path + recon".
// Same rule as app.js: only textContent, never innerHTML.
const Path = (() => {
  const stages = new Set(["dns", "hop", "tcp", "tls", "http"]);
  const byId = (id) => document.getElementById(id);

  let cy = null;
  let currentTarget = "";
  let resolvedIp = null;
  let destNodeId = null;
  let prevNodeId = null;
  let prevDashed = false;
  let nodeCount = 0;

  const STYLE = [
    {
      selector: "node",
      style: {
        "background-color": "#06140e", "border-width": 2, "border-color": "#2bff9a",
        "label": "data(label)", "color": "#cfeee0", "font-family": "Courier New, monospace",
        "font-size": 11, "text-wrap": "wrap", "text-valign": "bottom", "text-margin-y": 8,
        "width": 26, "height": 26,
      },
    },
    { selector: "node.you", style: { "border-color": "#b78cff" } },
    { selector: "node.private", style: { "border-color": "#8fbfa8" } },
    { selector: "node.unknown", style: { "border-style": "dashed", "border-color": "#ffc247" } },
    { selector: "node.destination", style: { "background-color": "#2bff9a", "width": 36, "height": 36 } },
    { selector: "node:selected", style: { "border-color": "#ffffff", "border-width": 3 } },
    {
      selector: "edge",
      style: {
        "width": 2, "line-color": "#1d7a56", "target-arrow-color": "#1d7a56",
        "target-arrow-shape": "triangle", "curve-style": "bezier",
      },
    },
    { selector: "edge.dashed", style: { "line-style": "dashed" } },
  ];

  function renderKV(elementId, obj) {
    const dl = byId(elementId);
    dl.replaceChildren();
    for (const [key, value] of Object.entries(obj)) {
      const dt = document.createElement("dt");
      dt.textContent = key;
      const dd = document.createElement("dd");
      dd.textContent = value === null || value === undefined || value === "" ? "n/a" : String(value);
      dl.append(dt, dd);
    }
  }

  function describe(hop) {
    const location = [hop.city, hop.country].filter(Boolean).join(", ");
    const asn = hop.asn ? `AS${hop.asn} ${hop.asn_org || ""}`.trim() : "";
    return { location, asn };
  }

  function addHopRow(hop) {
    const { location, asn } = describe(hop);
    const values = [
      hop.hop,
      hop.ip || "* (no response)",
      hop.rtt_ms != null ? hop.rtt_ms.toFixed(1) : "",
      location,
      asn,
      hop.note || "",
    ];
    const row = document.createElement("tr");
    for (const value of values) {
      const cell = document.createElement("td");
      cell.textContent = value === "" ? "n/a" : value;
      row.appendChild(cell);
    }
    byId("hop-rows").appendChild(row);
  }

  // ----- graph -----

  function appendNode(id, label, classes, info, dashed) {
    cy.add({
      group: "nodes",
      data: { id, label, info },
      // preset positions: a left-to-right path with a slight zigzag so labels don't collide
      position: { x: nodeCount * 150, y: (nodeCount % 2) * 45 },
      classes,
    });
    if (prevNodeId) {
      cy.add({
        group: "edges",
        data: { id: `e-${prevNodeId}-${id}`, source: prevNodeId, target: id },
        classes: dashed || prevDashed ? "dashed" : "",
      });
    }
    prevNodeId = id;
    prevDashed = Boolean(dashed);
    nodeCount++;
    cy.fit(cy.elements(), 50);
  }

  function ensureGraph() {
    if (typeof cytoscape === "undefined") {
      renderKV("node-detail", { Notice: "Graph library did not load. The hop table still works." });
      return false;
    }
    if (!cy) {
      cy = cytoscape({ container: byId("graph"), elements: [], style: STYLE, minZoom: 0.3, maxZoom: 2.5 });
      cy.on("tap", "node", (evt) => renderKV("node-detail", evt.target.data("info")));
      window.addEventListener("resize", () => {
        cy.resize();
        cy.fit(cy.elements(), 50);
      });
    }
    cy.resize();
    if (cy.nodes().length === 0) {
      appendNode("you", "You", "you", { Role: "Your device (trace origin)" }, false);
      renderKV("node-detail", { Hint: "Click a node to see its details" });
    }
    return true;
  }

  function addHopNode(hop) {
    if (!ensureGraph()) return;
    const id = `hop-${hop.hop}`;
    const unknown = !hop.ip;
    const isPrivate = Boolean(hop.note) && hop.note.startsWith("private");
    const isDestination = Boolean(hop.ip) && hop.ip === resolvedIp;
    const rtt = hop.rtt_ms != null ? `${hop.rtt_ms.toFixed(0)} ms` : "";
    const { location, asn } = describe(hop);

    let label;
    let classes;
    if (unknown) {
      label = `hop ${hop.hop}\nno response`;
      classes = "unknown";
    } else if (isDestination) {
      label = `${currentTarget}\n${rtt}`;
      classes = "destination";
      destNodeId = id;
    } else {
      label = `${hop.ip}\n${rtt}`;
      classes = isPrivate ? "private" : "";
    }

    appendNode(id, label, classes, {
      "Hop": hop.hop,
      "IP": hop.ip || "no response (ICMP filtered or rate-limited)",
      "RTT (ms)": hop.rtt_ms != null ? hop.rtt_ms.toFixed(1) : null,
      "Location": location,
      "ASN": asn,
      "Note": hop.note,
    }, unknown);
  }

  // If the trace never showed the destination as a hop (silent final hops),
  // add it once TCP connects so the path still ends at the target.
  function ensureDestinationNode(ip) {
    if (destNodeId || !ensureGraph()) return;
    destNodeId = "dest";
    appendNode("dest", `${currentTarget}\n${ip}`, "destination", {
      "Host": currentTarget,
      "IP": ip,
      "Note": "Reached via TCP, but the traceroute did not show this final hop",
    }, true);
  }

  // ----- public -----

  function reset(target) {
    currentTarget = target;
    resolvedIp = null;
    destNodeId = null;
    prevNodeId = null;
    prevDashed = false;
    nodeCount = 0;
    if (cy) cy.elements().remove();
    for (const id of ["hop-rows", "dns-body", "tcp-body", "tls-body", "http-body", "node-detail"]) {
      byId(id).replaceChildren();
    }
  }

  function handle(stage, d) {
    if (stage === "dns") {
      resolvedIp = d.resolved_ip;
      renderKV("dns-body", {
        "Resolved IP": d.resolved_ip,
        "TTL": d.ttl,
        "Resolver": d.resolver,
        "All IPs": (d.all_ips || []).join(", "),
        "Error": d.error,
      });
    } else if (stage === "hop") {
      addHopRow(d);
      addHopNode(d);
    } else if (stage === "tcp") {
      if (d.connected) ensureDestinationNode(d.ip);
      renderKV("tcp-body", {
        "Connected": d.connected,
        "Port": d.port,
        "Connect time (ms)": d.connect_time_ms != null ? d.connect_time_ms.toFixed(1) : null,
        "Error": d.error,
      });
    } else if (stage === "tls") {
      renderKV("tls-body", {
        "Version": d.tls_version,
        "Cipher": d.cipher,
        "Cert subject": d.cert_subject,
        "Cert issuer": d.cert_issuer,
        "Cert expires": d.cert_expires,
        "Error": d.error,
      });
    } else if (stage === "http") {
      renderKV("http-body", {
        "Status": d.status_code,
        "Server": d.headers ? d.headers["Server"] : null,
        "Response time (ms)": d.response_time_ms != null ? d.response_time_ms.toFixed(0) : null,
        "Error": d.error,
      });
    }
  }

  return { stages, reset, handle };
})();