"use strict";

const token = sessionStorage.getItem("idp_access_token") || "";
const did = sessionStorage.getItem("idp_authenticated_did") || "";
const accountDid = document.getElementById("accountDid");
const tokenScope = document.getElementById("tokenScope");
const tokenExpiry = document.getElementById("tokenExpiry");
const profileCheck = document.getElementById("profileCheck");
const profileTitle = document.getElementById("profileTitle");
const profileMessage = document.getElementById("profileMessage");
const accountMessage = document.getElementById("accountMessage");
const signOutButton = document.getElementById("signOutButton");

function readTokenClaims(value) {
  try {
    const encoded = value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=");
    return JSON.parse(atob(padded));
  } catch {
    return {};
  }
}

function showMessage(message, state = "info") {
  accountMessage.textContent = message;
  const tone = ["error", "success"].includes(state) ? ` ${state}` : "";
  accountMessage.className = `login-message show${tone}`;
}

function clearSession() {
  [
    "idp_access_token",
    "idp_authenticated_did",
    "idp_auth_session",
    "idp_access_token_jti",
    "idp_access_token_expires_at",
    "idp_access_token_scope"
  ].forEach(key => sessionStorage.removeItem(key));
}

async function verifyProtectedProfile() {
  const response = await fetch("/api/v1/tokens/protected/profile", {
    headers: { Authorization: `Bearer ${token}` }
  });
  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(result.detail || "The protected profile request was denied.");
  }
  if (result.did !== did || result.allowed !== true) {
    throw new Error("The protected profile response did not match this account.");
  }

  profileCheck.dataset.state = "success";
  profileTitle.textContent = "Access granted";
  profileMessage.textContent = `The API verified your token and returned the protected profile for ${result.did}.`;
}

async function signOut() {
  const claims = readTokenClaims(token);
  const jti = sessionStorage.getItem("idp_access_token_jti") || claims.jti;
  if (!jti) {
    showMessage("Could not identify this access token for revocation. Please sign in again.", "error");
    return;
  }

  signOutButton.disabled = true;
  signOutButton.textContent = "Revoking token…";
  try {
    const response = await fetch("/api/v1/tokens/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ jti, reason: "User signed out" })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.revoked !== true) {
      throw new Error(result.detail || "The access token could not be revoked.");
    }

    clearSession();
    showMessage("Your access token was revoked. Returning to login…", "success");
    window.setTimeout(() => window.location.replace("/login"), 700);
  } catch (error) {
    showMessage(error.message || "Sign out could not be completed.", "error");
    signOutButton.disabled = false;
    signOutButton.textContent = "Sign out and revoke token";
  }
}

signOutButton.addEventListener("click", signOut);

if (!token || !did) {
  window.location.replace("/login");
} else {
  const claims = readTokenClaims(token);
  const expiry = Number(sessionStorage.getItem("idp_access_token_expires_at"))
    || (claims.exp ? Number(claims.exp) * 1000 : 0);
  let scopes = [];
  try {
    scopes = JSON.parse(sessionStorage.getItem("idp_access_token_scope") || "[]");
  } catch {
    scopes = [];
  }

  accountDid.textContent = did;
  tokenScope.textContent = scopes.length ? scopes.join(", ") : (claims.scope || "read:profile");
  tokenExpiry.textContent = expiry ? new Date(expiry).toLocaleString() : "Short-lived";
  verifyProtectedProfile().catch(error => {
    profileCheck.dataset.state = "error";
    profileTitle.textContent = "Access check failed";
    profileMessage.textContent = error.message;
    showMessage("Your session is open, but the protected API request failed.", "error");
  });
}
