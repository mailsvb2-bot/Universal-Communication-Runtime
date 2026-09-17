"use strict";

const root = document.documentElement;
const directionToggle = document.getElementById("direction-toggle");
const textScale = document.getElementById("text-scale");
const contrastToggle = document.getElementById("contrast-toggle");
const accessibilityStatus = document.getElementById("accessibility-status");
const allowedScales = new Set(["100", "125", "150"]);

function announce(message) {
  accessibilityStatus.textContent = message;
}

directionToggle.addEventListener("click", () => {
  const nextDirection = root.dir === "rtl" ? "ltr" : "rtl";
  root.dir = nextDirection;
  const rtlEnabled = nextDirection === "rtl";
  directionToggle.setAttribute("aria-pressed", String(rtlEnabled));
  directionToggle.textContent = rtlEnabled ? "Use left-to-right layout" : "Use right-to-left layout";
  announce(rtlEnabled ? "Right-to-left layout enabled" : "Left-to-right layout enabled");
});

textScale.addEventListener("change", () => {
  if (!allowedScales.has(textScale.value)) return;
  root.dataset.textScale = textScale.value;
  announce(`Text size ${textScale.value} percent`);
});

contrastToggle.addEventListener("click", () => {
  const enabled = root.dataset.contrast !== "high";
  if (enabled) root.dataset.contrast = "high";
  else delete root.dataset.contrast;
  contrastToggle.setAttribute("aria-pressed", String(enabled));
  contrastToggle.textContent = enabled ? "Use system contrast" : "Use high contrast";
  announce(enabled ? "High contrast enabled" : "System contrast enabled");
});
