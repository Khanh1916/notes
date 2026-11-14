/* writeups — progressive enhancements. Nothing here is required to read a post. */
(function () {
  "use strict";

  var d = document;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* --- theme toggle: auto -> light -> dark -------------------------------- */
  var ORDER = ["auto", "light", "dark"];
  var btn = d.getElementById("theme-toggle");

  function current() {
    try { return localStorage.getItem("writeups-theme") || "auto"; }
    catch (e) { return "auto"; }
  }

  function paint(mode) {
    if (mode === "auto") d.documentElement.removeAttribute("data-theme");
    else d.documentElement.setAttribute("data-theme", mode);
    if (!btn) return;
    var label = btn.querySelector(".theme-toggle__label");
    if (label) label.textContent = mode;
    btn.setAttribute("aria-label", "Theme: " + mode + " (click to change)");
    btn.title = "Theme: " + mode;
  }

  paint(current());

  if (btn) {
    btn.addEventListener("click", function () {
      var next = ORDER[(ORDER.indexOf(current()) + 1) % ORDER.length];
      try { localStorage.setItem("writeups-theme", next); } catch (e) {}
      paint(next);
    });
  }

  /* --- mail: copy the address (a bare mailto does nothing without a mail app) */
  var mail = d.querySelector("[data-copy]");
  if (mail && navigator.clipboard) {
    mail.addEventListener("click", function (e) {
      e.preventDefault();
      navigator.clipboard.writeText(mail.getAttribute("data-copy")).then(function () {
        var was = mail.textContent;
        mail.textContent = "copied";
        setTimeout(function () { mail.textContent = was; }, 1600);
      }, function () { window.location.href = mail.href; });
    });
  }

  /* --- reading progress --------------------------------------------------- */
  var bar = d.getElementById("progress");
  var top = d.getElementById("to-top");

  if (bar || top) {
    var tick = function () {
      var h = d.documentElement;
      var max = h.scrollHeight - h.clientHeight;
      var y = h.scrollTop || d.body.scrollTop;
      if (bar) bar.style.width = (max > 0 ? (y / max) * 100 : 0) + "%";
      if (top) top.classList.toggle("show", y > 600);
    };
    var queued = false;
    window.addEventListener("scroll", function () {
      if (queued) return;
      queued = true;
      requestAnimationFrame(function () { tick(); queued = false; });
    }, { passive: true });
    tick();
  }

  if (top) {
    top.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
    });
  }

  /* --- post page: anchors, TOC, code, figures ----------------------------- */
  var prose = d.querySelector(".prose");

  if (prose) {
    /* hover anchors on headings */
    prose.querySelectorAll("h2[id], h3[id]").forEach(function (h) {
      var a = d.createElement("a");
      a.className = "anchor";
      a.href = "#" + h.id;
      a.textContent = "#";
      a.setAttribute("aria-label", "Permalink to this section");
      h.appendChild(a);
    });

    /* copy buttons on code blocks */
    prose.querySelectorAll("pre").forEach(function (pre) {
      if (!navigator.clipboard) return;
      var b = d.createElement("button");
      b.type = "button";
      b.className = "copy";
      b.textContent = "copy";
      b.addEventListener("click", function () {
        var code = pre.querySelector("code");
        navigator.clipboard.writeText((code || pre).innerText).then(function () {
          b.textContent = "copied";
          b.classList.add("done");
          setTimeout(function () {
            b.textContent = "copy";
            b.classList.remove("done");
          }, 1400);
        });
      });
      pre.appendChild(b);
    });

    /* wide tables scroll inside a wrapper instead of shrinking to content */
    prose.querySelectorAll("table").forEach(function (t) {
      if (t.parentNode.classList.contains("table-wrap")) return;
      var w = d.createElement("div");
      w.className = "table-wrap";
      t.parentNode.insertBefore(w, t);
      w.appendChild(t);
    });

    /* alt text becomes a caption; the screenshot becomes a figure */
    prose.querySelectorAll("p > img").forEach(function (img) {
      var p = img.parentNode;
      if (p.childNodes.length !== 1) return;
      var fig = d.createElement("figure");
      var cap = d.createElement("figcaption");
      cap.textContent = img.getAttribute("alt") || "";
      fig.appendChild(img.cloneNode(true));
      if (cap.textContent) fig.appendChild(cap);
      p.parentNode.replaceChild(fig, p);
    });

    /* click a screenshot to see it full size */
    var box = d.getElementById("lightbox");
    if (box) {
      var boxImg = box.querySelector("img");
      var close = function () { box.hidden = true; boxImg.src = ""; };
      prose.addEventListener("click", function (e) {
        var img = e.target.closest("figure img, p > img");
        if (!img) return;
        boxImg.src = img.currentSrc || img.src;
        boxImg.alt = img.alt || "";
        box.hidden = false;
      });
      box.addEventListener("click", close);
      d.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && !box.hidden) close();
      });
    }

    /* table of contents, built from the visible language only */
    var toc = d.getElementById("toc");
    if (toc) {
      var build = function () {
        var list = d.createElement("ol");
        var seen = [];
        prose.querySelectorAll("h2[id], h3[id]").forEach(function (h) {
          if (!h.offsetParent && h.offsetHeight === 0) return; /* hidden language */
          var li = d.createElement("li");
          li.className = "lvl-" + h.tagName.charAt(1);
          var a = d.createElement("a");
          a.href = "#" + h.id;
          a.textContent = [].filter.call(h.childNodes, function (n) {
            return !(n.nodeType === 1 && n.classList.contains("anchor"));
          }).map(function (n) { return n.textContent; }).join("").trim();
          li.appendChild(a);
          list.appendChild(li);
          seen.push({ h: h, a: a });
        });
        toc.querySelectorAll("ol").forEach(function (o) { o.remove(); });
        toc.appendChild(list);
        toc.hidden = seen.length < 3;
        return seen;
      };

      var items = build();
      d.addEventListener("writeups:langchange", function () { items = build(); });

      /* highlight the section being read */
      var mark = function () {
        var y = window.scrollY + 120;
        var active = null;
        items.forEach(function (it) {
          if (it.h.getBoundingClientRect().top + window.scrollY <= y) active = it.a;
        });
        items.forEach(function (it) { it.a.classList.toggle("active", it.a === active); });
      };
      var q = false;
      window.addEventListener("scroll", function () {
        if (q) return;
        q = true;
        requestAnimationFrame(function () { mark(); q = false; });
      }, { passive: true });
      mark();
    }
  }

  /* --- home: filter by tag ------------------------------------------------ */
  var filters = d.getElementById("filters");
  if (filters) {
    var entries = [].slice.call(d.querySelectorAll(".entry"));
    var count = d.getElementById("entry-count");
    var empty = d.getElementById("entries-empty");

    filters.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b) return;
      var tag = b.getAttribute("data-tag");
      filters.querySelectorAll("button").forEach(function (o) {
        o.setAttribute("aria-pressed", String(o === b));
      });
      var shown = 0;
      entries.forEach(function (li) {
        var tags = (li.getAttribute("data-tags") || "").split(" ");
        var ok = tag === "*" || tags.indexOf(tag) !== -1;
        li.hidden = !ok;
        if (ok) shown++;
      });
      if (count) count.textContent = shown;
      if (empty) empty.hidden = shown !== 0;
    });
  }
})();

/* --- language switch (used by the bilingual posts) ----------------------- */
function setWLang(l) {
  document.documentElement.classList.toggle("wlang-vi", l === "vi");
  ["en", "vi"].forEach(function (k) {
    var b = document.getElementById("wl-" + k);
    if (b) {
      b.classList.toggle("active", k === l);
      b.setAttribute("aria-pressed", String(k === l));
    }
  });
  document.documentElement.setAttribute("lang", l === "vi" ? "vi" : "en");
  try { localStorage.setItem("writeups-lang", l); } catch (e) {}
  document.dispatchEvent(new CustomEvent("writeups:langchange", { detail: l }));
}

(function () {
  if (!document.querySelector(".lang-switch")) return;
  var saved = "en";
  try { saved = localStorage.getItem("writeups-lang") || "en"; } catch (e) {}
  setWLang(saved);
})();
