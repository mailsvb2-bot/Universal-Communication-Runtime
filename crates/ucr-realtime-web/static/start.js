import {
  createUcrBrowserProtectedDeviceVault,
  createUcrFirstPartyCallEntry,
  createUcrFirstPartyHttpHost,
} from "/endpoint-media/reference_browser_media_installer.js";

const button = document.getElementById("begin");
const status = document.getElementById("status");
const vault = createUcrBrowserProtectedDeviceVault();
const host = createUcrFirstPartyHttpHost(vault, {origin: location.origin});
const begin = createUcrFirstPartyCallEntry(host, vault);
let busy = false;

button.addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  button.disabled = true;
  status.textContent = "Checking your account, Device and signed call permission…";
  try {
    const issued = await begin();
    // Never put the signed grant into the query string or an HTTP request.
    // The existing Conference client performs its own signature + lifetime
    // validation and server redemption before any media can be published.
    const url = new URL("/client.html", location.origin);
    url.hash = issued.joinFragment.slice(1);
    location.replace(url.href);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown authorization failure";
    status.textContent = "Protected call unavailable: " + message;
    button.disabled = false;
    busy = false;
  }
});
