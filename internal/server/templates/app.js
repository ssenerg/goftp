"use strict";
// Enhancements for goftp's pages, which work without them. The server's CSP
// admits this script by its hash.
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const human = n => {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    return i ? `${n.toFixed(1)} ${units[i]}` : `${n} B`;
  };

  // Confirmations are shown once, not again on reload.
  const params = new URLSearchParams(location.search);
  if (params.has("uploaded") || params.has("created")) {
    params.delete("uploaded");
    params.delete("created");
    history.replaceState(null, "", location.pathname + (params.size ? "?" + params : ""));
  }

  // Times in the visitor's time zone.
  const when = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  for (const t of $$("time[datetime]")) {
    const d = new Date(t.dateTime);
    if (!Number.isNaN(d.getTime())) {
      t.title = t.textContent;
      t.textContent = when.format(d);
    }
  }

  // Filtering the listing; "/" jumps to the filter, Escape clears it.
  const filter = $("#filter");
  if (filter) {
    $("#search").hidden = false;
    const rows = $$("tr[data-name]");
    const none = $("#no-match");
    const apply = () => {
      const q = filter.value.trim().toLowerCase();
      let shown = 0;
      for (const row of rows) {
        row.hidden = q !== "" && !row.dataset.name.includes(q);
        if (!row.hidden) shown++;
      }
      none.hidden = shown > 0;
    };
    filter.addEventListener("input", apply);
    document.addEventListener("keydown", e => {
      const typing = e.target.closest && e.target.closest("input, textarea, select");
      if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        filter.focus();
      } else if (e.key === "Escape" && e.target === filter) {
        filter.value = "";
        apply();
        filter.blur();
      }
    });
  }

  // New folder: a popover whose errors show in place.
  const box = $(".newfolder");
  if (box) {
    const form = $("form", box);
    const name = $("input[name=folder]", form);
    const error = $(".popover-error", form);
    box.addEventListener("toggle", () => {
      if (box.open) name.focus();
    });
    box.addEventListener("keydown", e => {
      if (e.key === "Escape" && box.open) {
        box.open = false;
        $("summary", box).focus();
      }
    });
    document.addEventListener("click", e => {
      if (box.open && !box.contains(e.target)) box.open = false;
    });
    const submit = $("button[type=submit]", form);
    form.addEventListener("submit", async e => {
      e.preventDefault();
      const folder = name.value.trim();
      let status = 400;
      if (folder !== "") {
        submit.disabled = true;
        try {
          status = (await fetch(form.action, { method: "POST", body: new URLSearchParams({ folder }) })).status;
        } catch {
          status = 0;
        }
        submit.disabled = false;
      }
      if (status === 201) {
        location.assign(form.action + "?created=" + encodeURIComponent(folder));
        return;
      }
      error.textContent = {
        0: "The connection was lost. Try again.",
        400: "Folder names cannot be empty or very long, start with a dot, or contain /, \\ or control characters.",
        401: "You were signed out. Sign in and try again.",
        403: "You may not create folders here.",
        409: "Something with this name already exists here.",
      }[status] || `The folder could not be created (error ${status}).`;
      error.hidden = false;
      name.select();
    });
  }

  // Password fields: show/hide, and a warning while Caps Lock is on.
  for (const input of $$(".pw input")) {
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "pw-toggle";
    const show = visible => {
      input.type = visible ? "text" : "password";
      toggle.textContent = visible ? "Hide" : "Show";
      toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
    };
    show(false);
    toggle.addEventListener("click", () => {
      show(input.type === "password");
      input.focus();
    });
    input.parentElement.append(toggle);

    const caps = input.closest(".field").querySelector(".caps");
    if (caps) {
      const check = e => {
        if (e.getModifierState) caps.hidden = !e.getModifierState("CapsLock");
      };
      input.addEventListener("keydown", check);
      input.addEventListener("keyup", check);
      input.addEventListener("blur", () => { caps.hidden = true; });
    }
  }

  // Choosing a new password: live hints.
  const next = $("input[name=new_password]");
  const confirm = $("input[name=confirm_password]");
  if (next && confirm) {
    const long = $("#hint-length");
    const same = $("#hint-match");
    const update = () => {
      long.classList.toggle("ok", [...next.value].length >= next.minLength);
      const match = confirm.value !== "" && confirm.value === next.value;
      same.classList.toggle("ok", match);
      confirm.setCustomValidity(confirm.value && !match ? "The new passwords do not match." : "");
    };
    next.addEventListener("input", update);
    confirm.addEventListener("input", update);
  }

  // Uploads: files chosen or dropped anywhere on the page are sent one by
  // one, with progress.
  const form = $("#upload");
  if (!form) return;
  const picker = $("input[type=file]", form);
  const replace = $("input[name=replace]", form);
  const panel = $("#transfers");
  const overlay = $("#drop");
  let active = 0;
  let failed = 0;
  let done = 0;

  const icon = id => {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "i");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(ns, "use");
    use.setAttribute("href", "#i-" + id);
    svg.append(use);
    return svg;
  };

  const heading = () => {
    let h = $("h2", panel);
    if (!h) {
      h = document.createElement("h2");
      panel.prepend(h);
    }
    h.replaceChildren();
    const text = document.createElement("span");
    if (active) {
      text.textContent = `Uploading… ${done} of ${done + failed + active} done`;
      h.append(text);
    } else {
      text.textContent = failed ? `${done} uploaded, ${failed} failed` : `${done} uploaded`;
      const refresh = document.createElement("a");
      refresh.href = form.action;
      refresh.className = "btn small";
      refresh.textContent = "Refresh list";
      h.append(text, refresh);
    }
    panel.hidden = false;
  };

  const row = (name, meta, id) => {
    const r = document.createElement("div");
    r.className = "transfer";
    const n = document.createElement("span");
    n.className = "transfer-name";
    n.textContent = name;
    const m = document.createElement("span");
    m.className = "transfer-meta";
    m.textContent = meta;
    r.append(icon(id), n, m);
    panel.append(r);
    return { r, m };
  };

  const reason = status => {
    switch (status) {
      case 0: return "The connection was lost.";
      case 400: return "This file name is not allowed.";
      case 401: return "You were signed out. Sign in and try again.";
      case 403: return replace && !replace.checked
        ? "You may not upload this here."
        : "You may not upload or replace this here.";
      case 409: return replace && !replace.checked
        ? "Already exists: tick “Replace files that already exist”, or rename it."
        : "A file or folder with this name exists or is being uploaded.";
      case 413: return "The file is too large.";
      case 507: return "The server is out of disk space.";
      default: return `Upload failed (error ${status}).`;
    }
  };

  const send = file => new Promise(resolve => {
    const t = row(file.name, human(file.size), "clock");
    const bar = document.createElement("progress");
    bar.max = 1;
    bar.value = 0;
    t.r.append(bar);
    const data = new FormData();
    if (replace && replace.checked) data.append("replace", "1");
    data.append("file", file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.upload.addEventListener("progress", e => {
      if (e.lengthComputable) {
        bar.value = e.loaded / e.total;
        t.m.textContent = `${human(e.loaded)} of ${human(e.total)}`;
      }
    });
    const finish = ok => {
      t.r.classList.add(ok ? "done" : "failed");
      t.r.firstChild.replaceWith(icon(ok ? "check" : "alert"));
      t.m.textContent = ok ? human(file.size) : reason(xhr.status);
      resolve(ok);
    };
    xhr.addEventListener("load", () => finish(xhr.status === 201));
    xhr.addEventListener("error", () => finish(false));
    xhr.send(data);
  });

  const upload = async files => {
    if (!files.length) return;
    const banner = $("#uploaded");
    if (banner) banner.remove();
    active += files.length;
    heading();
    for (const file of files) {
      const ok = await send(file);
      active--;
      if (ok) done++;
      else failed++;
      heading();
    }
    if (!active && !failed) location.assign(form.action + "?uploaded=" + done);
  };

  picker.addEventListener("change", () => {
    const files = [...picker.files];
    picker.value = "";
    upload(files);
  });

  addEventListener("beforeunload", e => {
    if (active) e.preventDefault();
  });

  const carriesFiles = e => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
  let depth = 0;
  document.addEventListener("dragenter", e => {
    if (carriesFiles(e)) {
      depth++;
      overlay.hidden = false;
    }
  });
  document.addEventListener("dragleave", e => {
    if (carriesFiles(e) && --depth <= 0) {
      depth = 0;
      overlay.hidden = true;
    }
  });
  document.addEventListener("dragover", e => {
    if (carriesFiles(e)) e.preventDefault();
  });
  document.addEventListener("drop", e => {
    if (!carriesFiles(e)) return;
    e.preventDefault();
    depth = 0;
    overlay.hidden = true;
    const files = [];
    for (const item of e.dataTransfer.items) {
      const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
      if (entry && entry.isDirectory) {
        row(entry.name, "Folders cannot be uploaded; drop the files inside it.", "alert").r.classList.add("failed");
        failed++;
        heading();
      } else if (item.kind === "file") {
        const f = item.getAsFile();
        if (f) files.push(f);
      }
    }
    upload(files);
  });
})();
