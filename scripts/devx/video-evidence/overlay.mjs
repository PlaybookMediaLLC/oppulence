/**
 * Restrained engineering annotation overlay for live Playwright browser recordings.
 * Renders a smooth visible cursor (hotspot aligned at 0,0), click ripple indicators,
 * element bounding boxes, measured numbered callouts clamped to the viewport safe area,
 * and optional smooth zoom that clears its transform on reset.
 */

const OVERLAY_ROOT_ID = "__pr_video_evidence_overlay__";

export async function installOverlay(page) {
  await page.evaluate((rootId) => {
    if (document.getElementById(rootId)) return;

    const style = document.createElement("style");
    style.id = `${rootId}_style`;
    style.textContent = `
      #${rootId} {
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 2147483640;
        overflow: hidden;
        font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }
      #${rootId}_cursor {
        position: fixed;
        top: 0;
        left: 0;
        width: 28px;
        height: 28px;
        transform: translate3d(960px, 540px, 0);
        transition: transform 420ms cubic-bezier(0.22, 1, 0.36, 1);
        filter: drop-shadow(0 3px 6px rgba(15, 23, 42, 0.42));
        will-change: transform;
      }
      #${rootId}_box {
        position: fixed;
        border: 2.5px solid #2563EB;
        border-radius: 10px;
        background: rgba(37, 99, 235, 0.08);
        box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.16), 0 8px 24px rgba(15, 23, 42, 0.14);
        opacity: 0;
        transition: opacity 220ms ease, left 260ms ease, top 260ms ease, width 260ms ease, height 260ms ease;
      }
      #${rootId}_callout {
        position: fixed;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 13px;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.92);
        color: #F8FAFC;
        border: 1px solid rgba(148, 163, 184, 0.35);
        font-size: 14px;
        font-weight: 600;
        letter-spacing: -0.01em;
        line-height: 1.2;
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.28);
        opacity: 0;
        transition: opacity 220ms ease, left 260ms ease, top 260ms ease;
        white-space: nowrap;
      }
      #${rootId}_callout .badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 22px;
        height: 22px;
        border-radius: 999px;
        background: #2563EB;
        color: #FFFFFF;
        font-size: 12px;
        font-weight: 700;
      }
      .${rootId}_ripple {
        position: fixed;
        width: 18px;
        height: 18px;
        margin-left: -9px;
        margin-top: -9px;
        border-radius: 999px;
        border: 3px solid #2563EB;
        background: rgba(37, 99, 235, 0.22);
        animation: ${rootId}_ripple_anim 560ms cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      @keyframes ${rootId}_ripple_anim {
        0% { transform: scale(0.6); opacity: 0.95; }
        100% { transform: scale(2.8); opacity: 0; }
      }
    `;
    document.head.appendChild(style);

    const root = document.createElement("div");
    root.id = rootId;

    const box = document.createElement("div");
    box.id = `${rootId}_box`;
    root.appendChild(box);

    const callout = document.createElement("div");
    callout.id = `${rootId}_callout`;
    callout.innerHTML = `<span class="badge">1</span><span class="label"></span>`;
    root.appendChild(callout);

    // SVG pointer tip is anchored at (1, 1) so translate3d(x, y, 0) points right at (x, y).
    const cursor = document.createElement("div");
    cursor.id = `${rootId}_cursor`;
    cursor.innerHTML = `
      <svg viewBox="0 0 28 28" width="28" height="28" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M1 1L18 12.2L10.1 13.8L6.3 21.2L1 1Z" fill="#0F172A" stroke="#FFFFFF" stroke-width="2" stroke-linejoin="round"/>
      </svg>
    `;
    root.appendChild(cursor);

    document.body.appendChild(root);
  }, OVERLAY_ROOT_ID);
}

export async function moveCursorTo(page, x, y, waitMs = 460) {
  await installOverlay(page);
  await page.mouse.move(x, y, { steps: 12 });
  await page.evaluate(
    ({ rootId, targetX, targetY }) => {
      const cursor = document.getElementById(`${rootId}_cursor`);
      if (cursor) {
        cursor.style.transform = `translate3d(${Math.round(targetX)}px, ${Math.round(targetY)}px, 0)`;
      }
    },
    { rootId: OVERLAY_ROOT_ID, targetX: x, targetY: y },
  );
  if (waitMs > 0) {
    await page.waitForTimeout(waitMs);
  }
}

export async function showClickRipple(page, x, y) {
  await installOverlay(page);
  await page.evaluate(
    ({ rootId, targetX, targetY }) => {
      const root = document.getElementById(rootId);
      if (!root) return;
      const ripple = document.createElement("div");
      ripple.className = `${rootId}_ripple`;
      ripple.style.left = `${Math.round(targetX)}px`;
      ripple.style.top = `${Math.round(targetY)}px`;
      root.appendChild(ripple);
      window.setTimeout(() => ripple.remove(), 620);
    },
    { rootId: OVERLAY_ROOT_ID, targetX: x, targetY: y },
  );
}

export async function highlightLocator(
  page,
  locator,
  { stepNumber = 1, label = "", padding = 8, placement = "auto" } = {},
) {
  await installOverlay(page);
  await locator.scrollIntoViewIfNeeded();
  const box = await locator.boundingBox();
  if (!box) return null;

  await page.evaluate(
    ({ rootId, rect, step, text, pad, prefPlacement }) => {
      const boxEl = document.getElementById(`${rootId}_box`);
      const calloutEl = document.getElementById(`${rootId}_callout`);
      if (!boxEl || !calloutEl) return;

      const left = Math.max(8, rect.x - pad);
      const top = Math.max(8, rect.y - pad);
      const width = Math.min(window.innerWidth - left - 8, rect.width + pad * 2);
      const height = Math.min(window.innerHeight - top - 8, rect.height + pad * 2);

      boxEl.style.left = `${Math.round(left)}px`;
      boxEl.style.top = `${Math.round(top)}px`;
      boxEl.style.width = `${Math.round(width)}px`;
      boxEl.style.height = `${Math.round(height)}px`;
      boxEl.style.opacity = "1";

      if (text) {
        const badge = calloutEl.querySelector(".badge");
        const labelSpan = calloutEl.querySelector(".label");
        if (badge) badge.textContent = String(step);
        if (labelSpan) labelSpan.textContent = text;

        const measuredWidth = Math.ceil(calloutEl.getBoundingClientRect().width) || 280;
        const measuredHeight = Math.ceil(calloutEl.getBoundingClientRect().height) || 36;

        let calloutLeft = left;
        let calloutTop = top - measuredHeight - 10;

        if (
          prefPlacement === "right" &&
          left + width + 14 + measuredWidth < window.innerWidth - 16
        ) {
          calloutLeft = left + width + 14;
          calloutTop = top + Math.max(0, (height - measuredHeight) / 2);
        } else if (prefPlacement === "below" || top < measuredHeight + 24) {
          calloutTop = Math.min(window.innerHeight - 155, top + height + 10);
        }

        calloutLeft = Math.max(16, Math.min(window.innerWidth - measuredWidth - 16, calloutLeft));
        calloutTop = Math.max(12, Math.min(window.innerHeight - 155, calloutTop));

        calloutEl.style.left = `${Math.round(calloutLeft)}px`;
        calloutEl.style.top = `${Math.round(calloutTop)}px`;
        calloutEl.style.opacity = "1";
      } else {
        calloutEl.style.opacity = "0";
      }
    },
    {
      rootId: OVERLAY_ROOT_ID,
      rect: box,
      step: stepNumber,
      text: label,
      pad: padding,
      prefPlacement: placement,
    },
  );

  return box;
}

export async function clearHighlight(page) {
  await page.evaluate((rootId) => {
    const boxEl = document.getElementById(`${rootId}_box`);
    const calloutEl = document.getElementById(`${rootId}_callout`);
    if (boxEl) boxEl.style.opacity = "0";
    if (calloutEl) calloutEl.style.opacity = "0";
  }, OVERLAY_ROOT_ID);
}

export async function clickLocatorWithIndicator(page, locator, options = {}) {
  const box = await highlightLocator(page, locator, options);
  if (box) {
    const cx = box.x + box.width / 2;
    const cy = box.y + box.height / 2;
    await moveCursorTo(page, cx, cy, 480);
    await showClickRipple(page, cx, cy);
    await page.waitForTimeout(160);
  }
  await locator.click();
}

export async function setRestrainedZoom(page, box, scale = 1.16) {
  const clampedScale = Math.max(1, Math.min(1.28, scale));
  await page.evaluate(
    ({ rect, zoom }) => {
      const target = document.documentElement;
      target.style.transition = "transform 520ms cubic-bezier(0.22, 1, 0.36, 1)";
      if (!rect || zoom <= 1.01) {
        target.style.transform = "";
        target.style.transformOrigin = "";
        return;
      }
      const ox = Math.max(15, Math.min(85, ((rect.x + rect.width / 2) / window.innerWidth) * 100));
      const oy = Math.max(
        15,
        Math.min(78, ((rect.y + rect.height / 2) / window.innerHeight) * 100),
      );
      target.style.transformOrigin = `${ox.toFixed(1)}% ${oy.toFixed(1)}%`;
      target.style.transform = `scale(${zoom})`;
    },
    { rect: box, zoom: clampedScale },
  );
  await page.waitForTimeout(560);
}
