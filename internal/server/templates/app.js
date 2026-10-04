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
  const shown = ["uploaded", "created", "renamed", "deleted"].filter(p => params.has(p));
  if (shown.length) {
    for (const p of shown) params.delete(p);
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

  // Rename and delete: a popover for each entry, made from a template.
  const itemForms = $("#item-actions");
  if (itemForms) {
    const failed = {
      rename: {
        0: "The connection was lost. Try again.",
        400: "Names cannot be empty or very long, start with a dot, or contain /, \\ or control characters.",
        401: "You were signed out. Sign in and try again.",
        403: "You may not rename this.",
        404: "It is no longer here. Reload the page.",
        409: "Something with this name already exists here, or one of them is being uploaded.",
      },
      delete: {
        0: "The connection was lost. Try again.",
        401: "You were signed out. Sign in and try again.",
        403: "You may not delete this, or something in it.",
        404: "It is no longer here. Reload the page.",
        409: "It, or something in it, is being uploaded right now, or another disk is mounted in it.",
      },
    };
    let open = null;
    const close = focus => {
      if (!open) return;
      open.pop.remove();
      open.link.setAttribute("aria-expanded", "false");
      if (focus) open.link.focus();
      open = null;
    };
    const show = link => {
      const name = link.dataset.item;
      const isDir = link.dataset.dir === "true";
      const pop = document.createElement("div");
      pop.className = "popover item-pop";
      pop.setAttribute("role", "dialog");
      pop.setAttribute("aria-label", link.getAttribute("aria-label"));
      pop.append(itemForms.content.cloneNode(true));
      for (const form of $$("form", pop)) {
        const kind = form.dataset.kind;
        const error = $(".popover-error", form);
        const submit = $("button[type=submit]", form);
        form.hidden = kind === "rename" && link.dataset.rename !== "true";
        form.elements[kind].value = name;
        form.addEventListener("submit", async e => {
          e.preventDefault();
          const to = kind === "rename" ? form.elements.to.value.trim() : "";
          if (kind === "rename" && to === name) {
            close(true);
            return;
          }
          let status = 400;
          if (kind === "delete" || to !== "") {
            const body = new URLSearchParams(new FormData(form));
            if (kind === "rename") body.set("to", to);
            submit.disabled = true;
            try {
              status = (await fetch(form.action, { method: "POST", body })).status;
            } catch {
              status = 0;
            }
            submit.disabled = false;
          }
          if (status === 201 || status === 204) {
            location.assign(form.action + (kind === "rename" ? "?renamed=" + encodeURIComponent(to) : "?deleted=1"));
            return;
          }
          error.textContent = failed[kind][status] || `It could not be ${kind}d (error ${status}).`;
          error.hidden = false;
          if (kind === "rename") form.elements.to.select();
        });
      }
      $(".delete-note", pop).textContent = isDir
        ? `Delete the folder “${name}” and everything in it? This cannot be undone.`
        : `Delete “${name}”? This cannot be undone.`;
      link.after(pop);
      // Upwards when it would end below the window and fits above.
      const box = pop.getBoundingClientRect();
      if (box.bottom > innerHeight && box.height < link.getBoundingClientRect().top) pop.classList.add("up");
      link.setAttribute("aria-expanded", "true");
      open = { pop, link };
      const to = $("input[name=to]", pop);
      if (link.dataset.rename === "true") {
        to.value = name;
        to.focus();
        // The name without its extension, ready to be typed over.
        const dot = isDir ? -1 : name.lastIndexOf(".");
        to.setSelectionRange(0, dot > 0 ? dot : name.length);
      } else {
        $("form[data-kind=delete] button", pop).focus();
      }
    };
    document.addEventListener("click", e => {
      const link = e.target.closest && e.target.closest("a[data-item]");
      if (link) {
        e.preventDefault();
        const again = open && open.link === link;
        close(false);
        if (!again) show(link);
      } else if (open && !open.pop.contains(e.target)) {
        close(false);
      }
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && open) close(true);
    });
  }

  // Copy buttons, for temporary passwords and links shown once.
  for (const button of $$("button[data-copy]")) {
    const source = document.getElementById(button.dataset.copy);
    if (!source || !navigator.clipboard) continue;
    button.hidden = false;
    button.addEventListener("click", async () => {
      const label = button.lastChild;
      try {
        await navigator.clipboard.writeText(source.textContent.trim());
        label.textContent = "Copied";
      } catch {
        getSelection().selectAllChildren(source);
        label.textContent = "Select and copy";
      }
    });
  }

  // Confirmation popovers close on Escape and on clicks elsewhere.
  for (const box of $$("details.confirm")) {
    box.addEventListener("keydown", e => {
      if (e.key === "Escape" && box.open) {
        box.open = false;
        $("summary", box).focus();
      }
    });
    document.addEventListener("click", e => {
      if (box.open && !box.contains(e.target)) box.open = false;
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
