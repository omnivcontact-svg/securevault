function b64urlToBytes(value) {
  const pad = "=".repeat((4 - value.length % 4) % 4);
  const base64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function bytesToB64url(bytes) {
  let s = "";
  bytes = new Uint8Array(bytes);
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCreationOptions(o) {
  o.challenge = b64urlToBytes(o.challenge);
  o.user.id = b64urlToBytes(o.user.id);
  if (o.excludeCredentials) {
    o.excludeCredentials.forEach(x => x.id = b64urlToBytes(x.id));
  }
  return o;
}

function decodeRequestOptions(o) {
  o.challenge = b64urlToBytes(o.challenge);
  if (o.allowCredentials) {
    o.allowCredentials.forEach(x => x.id = b64urlToBytes(x.id));
  }
  return o;
}

function credentialToJSON(cred) {
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
      ...(cred.response.attestationObject ? {attestationObject: bytesToB64url(cred.response.attestationObject)} : {}),
      ...(cred.response.authenticatorData ? {authenticatorData: bytesToB64url(cred.response.authenticatorData)} : {}),
      ...(cred.response.signature ? {signature: bytesToB64url(cred.response.signature)} : {}),
      ...(cred.response.userHandle ? {userHandle: bytesToB64url(cred.response.userHandle)} : {})
    },
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment
  };
}

async function getJSON(url) {
  const r = await fetch(url, {credentials: "same-origin"});
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}

async function registerPasskey() {
  const button = document.getElementById("registerPasskey");
  const status = document.getElementById("passkeyStatus");
  if (!status) return;
  if (!window.PublicKeyCredential || !navigator.credentials) {
    status.textContent = "This browser does not support passkeys/WebAuthn.";
    return;
  }

  button.disabled = true;
  status.textContent = "Preparing device registration…";
  try {
    const raw = await getJSON("/webauthn/register/options");
    const options = decodeCreationOptions(raw);
    const cred = await navigator.credentials.create({publicKey: options});
    if (!cred) throw new Error("The device did not create a passkey.");

    status.textContent = "Verifying your device passkey…";
    const vr = await fetch("/webauthn/register/verify", {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(credentialToJSON(cred))
    });
    const data = await vr.json().catch(() => ({}));
    if (!vr.ok || !data.ok) throw new Error(data.error || "Registration failed.");
    status.textContent = data.message || "Device passkey registered successfully.";
    setTimeout(() => window.location.reload(), 800);
  } catch (e) {
    status.textContent = "Passkey registration failed: " + (e.message || e);
  } finally {
    button.disabled = false;
  }
}

async function verifyBiometric() {
  const button = document.getElementById("bioBtn");
  const status = document.getElementById("bioStatus");
  if (!status) return;
  if (!window.PublicKeyCredential || !navigator.credentials) {
    status.textContent = "This browser does not support passkeys/WebAuthn.";
    return;
  }

  button.disabled = true;
  status.textContent = "Preparing device verification…";
  try {
    const raw = await getJSON("/webauthn/auth/options");
    const options = decodeRequestOptions(raw);
    status.textContent = "Approve the fingerprint, Face ID, Windows Hello, or passkey prompt…";
    const cred = await navigator.credentials.get({publicKey: options});
    if (!cred) throw new Error("The device did not return a credential.");

    status.textContent = "Checking the device response…";
    const vr = await fetch("/webauthn/auth/verify", {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(credentialToJSON(cred))
    });
    const data = await vr.json().catch(() => ({}));
    if (!vr.ok || !data.ok) throw new Error(data.error || "Verification failed.");
    window.location.href = data.redirect;
  } catch (e) {
    status.textContent = "Device verification failed: " + (e.message || e);
    button.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const reg = document.getElementById("registerPasskey");
  if (reg) reg.addEventListener("click", registerPasskey);
  const bio = document.getElementById("bioBtn");
  if (bio) bio.addEventListener("click", verifyBiometric);
});
