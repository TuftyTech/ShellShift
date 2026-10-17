// The whole client. No framework, no dependencies.
//
// Everything the page says is already painted by the time this runs: both languages are in the
// markup, CSS hides the one the document is not showing, and the rows of the node table are
// rendered. This file only adds the controls — theme, language, copy, filter, search — so the
// largest paint never waits on script execution.
(function () {
  "use strict";

  var root = document.documentElement;

  // Attributes cannot hold two languages the way text can, so the template renders the page's
  // language into aria-label and placeholder and the other one into a data- twin. Switching
  // exchanges the pair, which keeps it symmetric and needs no string table on this side.
  var TWINS = [
    ["aria-label", "data-alt-aria-label"],
    ["placeholder", "data-alt-placeholder"],
  ];

  function swapAttrs() {
    for (var i = 0; i < TWINS.length; i++) {
      var attr = TWINS[i][0], twin = TWINS[i][1];
      var nodes = document.querySelectorAll("[" + twin + "]");
      for (var j = 0; j < nodes.length; j++) {
        var el = nodes[j];
        var a = el.getAttribute(attr), b = el.getAttribute(twin);
        el.setAttribute(attr, b);
        el.setAttribute(twin, a);
      }
    }
  }

  function setLang(next) {
    if (next !== "ru" && next !== "en") return;
    if (root.getAttribute("data-lang") === next) return;
    root.setAttribute("data-lang", next);
    // lang has to move with it. Left behind, it tells assistive technology to pronounce the
    // visible text in the language it is not written in.
    root.setAttribute("lang", next);
    swapAttrs();
    var halves = document.querySelectorAll("[data-lang-to]");
    for (var i = 0; i < halves.length; i++) {
      if (halves[i].getAttribute("data-lang-to") === next) {
        halves[i].setAttribute("aria-current", "page");
      } else {
        halves[i].removeAttribute("aria-current");
      }
    }
    try {
      localStorage.setItem("ss-lang", next);
    } catch (e) {
      // A blocked storage is not a reason to refuse the switch.
    }
  }

  function wireLang() {
    var halves = document.querySelectorAll("[data-lang-to]");
    for (var i = 0; i < halves.length; i++) {
      halves[i].addEventListener("click", function (ev) {
        // Only the in-page swap is prevented. A modified click — new tab, new window — is
        // left to the browser, because the href is a real prerendered page.
        if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button !== 0) return;
        ev.preventDefault();
        setLang(this.getAttribute("data-lang-to"));
      });
    }
  }

  // Copy, with a fallback that is a real fallback. The predecessor opened a window.prompt
  // when the clipboard was unavailable, which is a dialog, not an affordance.
  function wireCopy() {
    var buttons = document.querySelectorAll("[data-testid=endpoint-copy]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var btn = this;
        var url = btn.getAttribute("data-url");
        // Scoped to the card, not to the button's parent: the button shares the head row
        // with the title and the field is the card's next child, so a parentElement lookup
        // finds nothing and the clipboard fallback silently stops selecting anything.
        var card = btn.closest("[data-testid=endpoint-card]");
        var field = card && card.querySelector("[data-testid=endpoint-url]");

        function selectInstead() {
          if (!field) return;
          field.focus();
          field.select();
          btn.setAttribute("data-state", "select");
        }

        function confirmed() {
          // The state is an attribute and the swap is CSS: both labels and both icons are
          // already inside the button. Assigning to textContent would delete every child it
          // has, and rewriting one label would strand the confirmation in one language.
          btn.setAttribute("data-state", "copied");
          var done = btn.querySelector(
            "[data-testid=endpoint-copy-done] [lang=" + root.getAttribute("data-lang") + "]");
          announce(done ? done.textContent : "");
          setTimeout(function () {
            btn.removeAttribute("data-state");
          }, 2000);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(url).then(confirmed, selectInstead);
        } else {
          selectInstead();
        }
      });
    }
  }

  // The success signal must reach assistive technology. In the predecessor the toast had no
  // role and no live region, so the single most important confirmation on the site was
  // announced to nobody.
  var liveRegion = null;
  function announce(text) {
    if (!liveRegion) {
      liveRegion = document.createElement("p");
      liveRegion.setAttribute("role", "status");
      liveRegion.setAttribute("aria-live", "polite");
      liveRegion.className = "sr-only";
      document.body.appendChild(liveRegion);
    }
    liveRegion.textContent = text;
  }

  function wireTheme() {
    var btn = document.querySelector("[data-testid=theme-toggle]");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try {
        localStorage.setItem("ss-theme", next);
      } catch (e) {
        // A blocked storage is not a reason to refuse the switch.
      }
    });
  }

  // The readout's age and band, recomputed from the timestamp the page carries.
  //
  // Everything else on this page is a measurement taken once and true forever. The age is not:
  // it was rendered as "0.0h ago · data is fresh" at build time and stayed that way, so the one
  // element whose job is to say "the pipeline may have stopped" said the opposite for as long as
  // the pipeline was stopped. The band is chosen from the same two edges Go used — read off
  // data-live-hours and data-aging-hours rather than copied here, so there is one threshold and
  // not two that can drift apart.
  //
  // Both bands and both languages are already in the markup; this sets one attribute and one
  // number, so a visitor with the script blocked still gets the band the run was rendered with.
  function ageReadout() {
    var strip = document.querySelector("[data-testid=heartbeat]");
    if (!strip) return;
    var stamp = strip.getAttribute("data-verified-at");
    var figure = strip.querySelector("[data-testid=heartbeat-age]");
    if (!stamp || !figure) return;

    var at = Date.parse(stamp);
    if (isNaN(at)) return;

    var live = parseFloat(strip.getAttribute("data-live-hours"));
    var aging = parseFloat(strip.getAttribute("data-aging-hours"));
    if (!(live > 0) || !(aging > live)) return;

    function tick() {
      // Clamped at zero: a visitor whose clock runs behind the runner's would otherwise be
      // shown a negative age, which reads as a broken page rather than as a skewed clock.
      var hours = Math.max(0, (Date.now() - at) / 3600000);
      figure.textContent = hours.toFixed(1);
      strip.setAttribute("data-freshness",
        hours < live ? "live" : hours < aging ? "aging" : "stale");
    }

    tick();
    // A page left open in a tab crosses an edge without a reload. Once a minute is far more
    // often than a two-hourly cadence needs and cheap enough not to matter.
    setInterval(tick, 60000);
  }


  // --- the node card ---------------------------------------------------------------------
  //
  // The detail of every node lives in network.json and nowhere in the markup. That is the whole
  // architecture of this feature, and not an optimisation: a card rendered per row would be about
  // 1.8 MB of HTML for a corpus this size, and it would put every node's credential into a page a
  // crawler indexes. So the payload is fetched once after the first paint, and the card is
  // assembled from labels that do ship in the markup — in both languages, like every other string
  // here, which is also what lets a Go test check them.
  //
  // Nothing below runs for a visitor with this file blocked, and nothing is missing for them
  // either: the table is complete, and the two controls the card needs are added by script rather
  // than rendered, because a button that cannot work is worse than no button.
  var payload = null;
  var extraHay = [];
  var applyFilter = null;

  // mask hides the middle of a value. Enough of both ends stays visible to recognise a node you
  // already have, which is the only reason to look at a credential at all.
  function mask(v) {
    if (!v) return "";
    if (v.length <= 12) return v.slice(0, 2) + "\u2026";
    return v.slice(0, 8) + "\u2026" + v.slice(-4);
  }

  function bytesText(n) {
    if (!n) return "";
    if (n >= 1048576) return (n / 1048576).toFixed(1) + " MiB";
    if (n >= 1024) return (n / 1024).toFixed(0) + " KiB";
    return String(n) + " B";
  }

  function dayOf(iso) {
    return typeof iso === "string" && iso.length >= 10 ? iso.slice(0, 10) : "";
  }

  // fieldText renders one row of the card. An absent value returns "" and the row is hidden
  // rather than shown empty: a label with nothing beside it reads as a measurement of nothing.
  function fieldText(node, d, field, shown) {
    switch (field) {
      case "uri":
        // Masked, the link is its scheme alone. Replacing the credential inside it was not enough:
        // the server stays in the authority, and Shadowsocks and VMess carry their secret base64-
        // encoded, so the plain credential never matched and the whole link went on screen.
        if (shown) return d.uri;
        var cut = d.uri.indexOf("://");
        return cut < 0 ? "\u2026" : d.uri.slice(0, cut + 3) + "\u2026";
      case "server":
        return shown ? d.server : mask(d.server);
      // The resolved address and its reverse name are the server again under another label:
      // left plain, the network section printed in full what the connection section had masked.
      case "addr":
        return shown ? d.addr || "" : mask(d.addr);
      case "ptr":
        return shown ? d.ptr || "" : mask(d.ptr);
      case "credential":
        return shown ? d.credential : mask(d.credential);
      case "port":
        return d.port ? String(d.port) : "";
      case "alpn":
        return d.alpn ? d.alpn.join(", ") : "";
      case "place":
        return [d.country, d.city].filter(Boolean).join(", ");
      case "latency":
        return node.latency_ms ? node.latency_ms + " ms" : "";
      case "mbps":
        return node.mbps ? node.mbps.toFixed(1) + " Mbit/s" : "";
      case "bytes":
        return bytesText(d.bytes);
      case "streak":
        return node.streak ? String(node.streak) : "";
      case "proofs":
        return d.proofs ? String(d.proofs) : "";
      case "failures":
        return d.failures ? String(d.failures) : "";
      case "first_seen":
        return dayOf(d.first_seen);
      case "class":
        return node.class || "";
      case "cover_subject":
        return d.cover ? d.cover.subject || "" : "";
      case "cover_issuer":
        return d.cover ? d.cover.issuer || "" : "";
      case "cover_tls":
        return d.cover ? d.cover.tls || "" : "";
      case "cover_valid":
        if (!d.cover || !d.cover.from || !d.cover.to) return "";
        return dayOf(d.cover.from) + " \u2014 " + dayOf(d.cover.to);
      case "stages":
        if (!d.stages) return "";
        return d.stages.map(function (st) {
          var line = st.stage + ": " + st.outcome;
          if (st.ms) line += " \u00b7 " + st.ms + " ms";
          if (st.reason) line += " \u00b7 " + st.reason;
          return line;
        }).join("\n");
      default:
        // Every other field name in detailSections() is the payload's own JSON name, so the
        // default branch is the whole implementation for them. That is enforced from Go:
        // TestTheCardsLabelsShipInBothLanguages walks NodeDetail's tags and fails on a field no
        // section shows — which is how `packet_encoding` was caught being called `encoding` here.
        return d[field] === undefined || d[field] === null ? "" : String(d[field]);
    }
  }

  // searchText is what the payload adds to a row's haystack, so that pasting an address or an SNI
  // finds the node it belongs to — the table prints neither.
  function searchText(node, d) {
    return [d.server, d.sni, d.host, d.addr, d.ptr, d.asn, d.isp, d.org, d.country, d.city,
            d.port ? String(d.port) : "", node.id].filter(Boolean).join(" ").toLowerCase();
  }

  function nodeCards() {
    var body = document.querySelector("[data-testid=node-rows]");
    var dialog = document.querySelector("[data-testid=node-detail]");
    var tpl = document.querySelector("[data-testid=node-detail-tpl]");
    var actionsTpl = document.querySelector("[data-testid=node-actions-tpl]");
    var src = root.getAttribute("data-payload");
    if (!body || !dialog || !tpl || !actionsTpl || !src || !dialog.showModal) return;

    var shell = dialog.querySelector("[data-nd=body]");
    shell.appendChild(tpl.content.cloneNode(true));
    var current = -1;

    function fill(index) {
      if (!payload || !payload.nodes || !payload.nodes[index]) return;
      var node = payload.nodes[index];
      var d = node.detail;
      if (!d) return;
      current = index;
      var shown = dialog.getAttribute("data-secret") === "shown";
      var idEl = dialog.querySelector("[data-nd=id]");
      if (idEl) idEl.textContent = node.id || "";
      var rows = shell.querySelectorAll("[data-field]");
      for (var i = 0; i < rows.length; i++) {
        var text = fieldText(node, d, rows[i].getAttribute("data-field"), shown);
        var val = rows[i].querySelector(".nd-val");
        if (val) val.textContent = text;
        rows[i].hidden = text === "";
      }
      // A section whose every row is hidden goes too, or the card grows empty headings.
      var secs = shell.querySelectorAll(".nd-sec");
      for (var k = 0; k < secs.length; k++) {
        secs[k].hidden = secs[k].querySelectorAll("[data-field]:not([hidden])").length === 0;
      }
    }

    function open(index) {
      fill(index);
      if (current >= 0) dialog.showModal();
    }

    function copyURI(index, btn) {
      if (!payload || !payload.nodes[index] || !payload.nodes[index].detail) return;
      var uri = payload.nodes[index].detail.uri;

      function confirmed() {
        // The same mechanism as the subscription button: an attribute, and CSS swaps the label
        // that is already inside the control in both languages.
        btn.setAttribute("data-state", "copied");
        setTimeout(function () { btn.removeAttribute("data-state"); }, 2000);
      }
      function fallback() {
        // No clipboard permission: put the line somewhere it can be selected by hand rather than
        // fail silently. The predecessor opened a window.prompt, which is a modal nobody can copy
        // out of on a phone.
        var box = dialog.querySelector(".nd-fallback") || document.createElement("textarea");
        box.className = "nd-fallback";
        box.readOnly = true;
        box.value = uri;
        if (!box.parentNode) dialog.appendChild(box);
        box.focus();
        box.select();
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(uri).then(confirmed, fallback);
      } else {
        fallback();
      }
    }

    function wireRows() {
      for (var i = 0; i < body.rows.length; i++) {
        var row = body.rows[i];
        var at = row.getAttribute("data-node");
        if (at === null) continue;
        var entry = payload.nodes[Number(at)];
        if (!entry || !entry.detail) continue;
        var cell = row.querySelector(".nact");
        if (cell) cell.appendChild(actionsTpl.content.cloneNode(true));
        extraHay[i] = searchText(entry, entry.detail);
      }
      body.addEventListener("click", function (ev) {
        var row = ev.target.closest ? ev.target.closest("tr[data-node]") : null;
        if (!row) return;
        var at = Number(row.getAttribute("data-node"));
        var copyBtn = ev.target.closest("[data-node-copy]");
        if (copyBtn) {
          copyURI(at, copyBtn);
          return;
        }
        open(at);
      });
      // A term typed before the fetch landed has to start matching when it does.
      if (applyFilter) applyFilter();
    }

    dialog.addEventListener("click", function (ev) {
      if (!ev.target.closest) return;
      if (ev.target.closest("[data-nd=close]")) {
        dialog.close();
        return;
      }
      var copyBtn = ev.target.closest("[data-nd=copy]");
      if (copyBtn) {
        copyURI(current, copyBtn);
        return;
      }
      if (ev.target.closest("[data-nd=reveal]")) {
        if (dialog.getAttribute("data-secret") === "shown") {
          dialog.removeAttribute("data-secret");
        } else {
          dialog.setAttribute("data-secret", "shown");
        }
        fill(current);
      }
    });
    // The secret goes back out of sight when the card closes. Left revealed, the next node a
    // reader opens would start with its credential on screen, which nobody asked for.
    dialog.addEventListener("close", function () {
      dialog.removeAttribute("data-secret");
      var box = dialog.querySelector(".nd-fallback");
      if (box) box.remove();
    });

    // After the first paint, and never before it: this file exists to add controls to a page that
    // is already readable, and a payload on the critical path would trade that away.
    function load() {
      fetch(src, { credentials: "omit" }).then(function (r) {
        return r.ok ? r.json() : null;
      }).then(function (data) {
        if (!data || !data.nodes) return;
        payload = data;
        wireRows();
      }).catch(function () {
        // A payload that does not arrive leaves the table exactly as it is. There is nothing to
        // report: the card was never on the page to break.
      });
    }
    if (window.requestIdleCallback) {
      window.requestIdleCallback(load, { timeout: 3000 });
    } else {
      setTimeout(load, 300);
    }
  }

  // The node table's filter and search.
  //
  // Both run over rows that are already in the document, so the table is complete and readable
  // with this file blocked. That is also why the tool row ships hidden and is revealed here: a
  // filter chip that cannot filter is worse than no chip, because it looks like the list is
  // narrower than it is.
  function wireNodes() {
    var tools = document.querySelector("[data-testid=node-tools]");
    var body = document.querySelector("[data-testid=node-rows]");
    if (!tools || !body) return;

    var rows = [], hay = [];
    for (var i = 0; i < body.rows.length; i++) {
      rows.push(body.rows[i]);
      // The haystack is built from the row's own text rather than rendered into the markup:
      // the row is the one piece of this page whose byte cost is multiplied by the size of the
      // corpus, and a duplicate of every cell would double it.
      hay.push(body.rows[i].textContent.toLowerCase());
    }

    var shown = document.querySelector("[data-testid=node-shown]");
    var nomatch = document.querySelector("[data-testid=node-nomatch]");
    var input = document.querySelector("[data-testid=node-search]");
    var chips = tools.querySelectorAll(".chip-btn");
    var proto = "", term = "";

    function apply() {
      var visible = 0;
      for (var i = 0; i < rows.length; i++) {
        var ok = (!proto || rows[i].getAttribute("data-p") === proto) &&
                 (!term || hay[i].indexOf(term) >= 0 ||
                  (extraHay[i] && extraHay[i].indexOf(term) >= 0));
        rows[i].hidden = !ok;
        if (ok) visible++;
      }
      if (shown) shown.textContent = String(visible);
      // An empty result says so. A table that simply goes blank reads as a broken page.
      if (nomatch) nomatch.hidden = visible !== 0;
    }

    for (var c = 0; c < chips.length; c++) {
      chips[c].addEventListener("click", function () {
        proto = this.getAttribute("data-filter") || "";
        for (var k = 0; k < chips.length; k++) {
          // aria-pressed is the single source of truth: the stylesheet follows it, so the chip
          // cannot look selected while telling a screen reader that it is not.
          chips[k].setAttribute("aria-pressed", chips[k] === this ? "true" : "false");
        }
        apply();
      });
    }

    if (input) {
      input.addEventListener("input", function () {
        term = this.value.trim().toLowerCase();
        apply();
      });
    }

    // Held so the card module can re-run the filter once the payload has widened the haystack.
    applyFilter = apply;
    tools.hidden = false;
    apply();
  }

  // The stored choices are applied before anything else runs.
  //
  // They cannot be applied any earlier than this. The policy this page carries is
  // `script-src 'self'` with no inline script permitted, so the one-line head script the
  // reference site uses to set an attribute before first paint is unavailable here, and a
  // deferred same-origin file is the earliest point there is. The tradeoff is deliberate: the
  // alternative was storing a choice on every click and forgetting it on every navigation,
  // which is a broken control. A brief flash is the smaller fault. Recorded as a limitation of
  // a host that cannot set headers (OQ-04).
  function restore() {
    try {
      var theme = localStorage.getItem("ss-theme");
      if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
      var lang = localStorage.getItem("ss-lang");
      if (lang) setLang(lang);
    } catch (e) {
      // A blocked storage is not a reason to refuse to render.
    }
  }

  restore();
  wireLang();
  wireTheme();
  wireCopy();
  wireNodes();
  ageReadout();
  nodeCards();
})();
