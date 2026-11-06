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
})();
