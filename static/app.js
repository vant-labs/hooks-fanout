(() => {
  const root = document.documentElement;
  const saved = localStorage.getItem("fanout-theme");
  if (saved === "dark" || saved === "light") root.dataset.theme = saved;

  document.addEventListener("click", async (event) => {
    const themeButton = event.target.closest("[data-theme-toggle]");
    if (themeButton) {
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      localStorage.setItem("fanout-theme", next);
    }
    const passwordButton = event.target.closest("[data-password-toggle]");
    if (passwordButton) {
      const password = document.querySelector(passwordButton.dataset.passwordTarget);
      if (!password) return;
      const visible = password.type === "password";
      password.type = visible ? "text" : "password";
      passwordButton.textContent = visible ? "Hide" : "Show";
      passwordButton.setAttribute("aria-label", `${visible ? "Hide" : "Show"} password`);
      passwordButton.setAttribute("aria-pressed", String(visible));
    }
    const copyButton = event.target.closest("[data-copy-target]");
    if (copyButton) {
      const target = document.querySelector(copyButton.dataset.copyTarget);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent);
        const original = copyButton.textContent;
        copyButton.textContent = "Copied";
        window.setTimeout(() => { copyButton.textContent = original; }, 1400);
      } catch (_) {
        copyButton.textContent = "Select to copy";
      }
    }
  });

  const liveEvents = document.querySelector("[data-live-events]");
  if (liveEvents && window.EventSource) {
    const stream = new EventSource(`/dashboard/events/live${window.location.search}`);
    stream.addEventListener("snapshot", (message) => {
      let payload;
      try {
        payload = JSON.parse(message.data);
      } catch (_) {
        return;
      }
      const events = Array.isArray(payload.events) ? payload.events : [];
      const empty = liveEvents.querySelector("[data-live-empty]");
      const table = liveEvents.querySelector("[data-live-table]");
      const body = liveEvents.querySelector("[data-live-event-body]");
      if (!empty || !table || !body) return;
      empty.hidden = events.length > 0;
      table.hidden = events.length === 0;
      body.replaceChildren(...events.map((item) => {
        const row = document.createElement("tr");
        const eventLink = document.createElement("a");
        eventLink.className = "event-id";
        eventLink.href = `/dashboard/events/${encodeURIComponent(item.id)}`;
        eventLink.textContent = item.id;
        const openLink = document.createElement("a");
        openLink.className = "text-link";
        openLink.href = eventLink.href;
        openLink.textContent = "Open";
        const values = [
          eventLink,
          item.event_type,
          item.source,
          item.matched_route || "Unrouted",
          item.status,
          new Date(item.received_at).toLocaleString(),
          openLink,
        ];
        values.forEach((value, index) => {
          const cell = document.createElement("td");
          if (index === 4) {
            const pill = document.createElement("span");
            pill.className = `pill pill-${["pending", "retrying", "delivered", "dead", "unrouted"].includes(value) ? value : "neutral"}`;
            pill.textContent = value;
            cell.appendChild(pill);
          } else if (value instanceof Node) {
            cell.appendChild(value);
          } else {
            cell.textContent = value;
          }
          row.appendChild(cell);
        });
        return row;
      }));
    });
  }
  const liveOverview = document.querySelector("[data-live-overview]");
  if (liveOverview && window.EventSource) {
    const stream = new EventSource(`/dashboard/overview/live${window.location.search}`);
    stream.addEventListener("snapshot", (message) => {
      let payload;
      try {
        payload = JSON.parse(message.data);
      } catch (_) {
        return;
      }
      if (payload.error) return;
      Object.entries(payload.stats || {}).forEach(([key, value]) => {
        document.querySelectorAll(`[data-live-value="${key}"]`).forEach((element) => {
          element.textContent = value;
        });
      });
      ["success_rate", "signature_failures"].forEach((key) => {
        const value = key === "success_rate" ? payload.success_rate : payload.signature_failures;
        document.querySelectorAll(`[data-live-value="${key}"]`).forEach((element) => {
          element.textContent = value;
        });
      });
      const updated = document.querySelector("[data-live-updated]");
      if (updated) updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
      const health = payload.health || {};
      const receivedPath = document.querySelector("[data-live-received-path]");
      const deliveredPath = document.querySelector("[data-live-delivered-path]");
      if (receivedPath && typeof health.received_path === "string") receivedPath.setAttribute("points", health.received_path);
      if (deliveredPath && typeof health.delivered_path === "string") deliveredPath.setAttribute("points", health.delivered_path);

      const recent = Array.isArray(payload.recent_failures) ? payload.recent_failures : [];
      const failures = document.querySelector("[data-live-failures]");
      if (!failures) return;
      const empty = failures.querySelector("[data-live-failure-empty]");
      const table = failures.querySelector("[data-live-failure-table]");
      const body = failures.querySelector("[data-live-failure-body]");
      if (!empty || !table || !body) return;
      empty.hidden = recent.length > 0;
      table.hidden = recent.length === 0;
      body.replaceChildren(...recent.map((item) => {
        const row = document.createElement("tr");
        const eventLink = document.createElement("a");
        eventLink.className = "event-id";
        eventLink.href = `/dashboard/events/${encodeURIComponent(item.id)}`;
        eventLink.textContent = item.id;
        const inspectLink = document.createElement("a");
        inspectLink.className = "text-link";
        inspectLink.href = eventLink.href;
        inspectLink.textContent = "Inspect";
        [eventLink, item.event_type, item.matched_route || "Unrouted", new Date(item.received_at).toLocaleString(), inspectLink]
          .forEach((value) => {
            const cell = document.createElement("td");
            if (value instanceof Node) cell.appendChild(value);
            else cell.textContent = value;
            row.appendChild(cell);
          });
        return row;
      }));
    });
  }
})();
