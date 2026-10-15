
const API = {
  registerOptions: "/webauthn/register/options",
  registerVerify: "/webauthn/register/verify",
  loginOptions: "/webauthn/login/options",
  loginVerify: "/webauthn/login/verify"
};

const usernameInput = document.getElementById("username");
const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");
const statusBox = document.getElementById("status");

function setStatus(message, state = "info") {
  statusBox.textContent = message;
  statusBox.dataset.state = state;
}

function base64urlToBuffer(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

function bufferToBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const responseText = await response.text();
  let data = {};

  if (responseText) {
    try {
      data = JSON.parse(responseText);
    } catch {
      data = { detail: responseText };
    }
  }

  if (!response.ok) {
    const message =
      typeof data.detail === "string"
        ? data.detail
        : `Request failed (${response.status}).`;

    throw new Error(message);
  }

  return data;
}

function getUsername() {
  const username = usernameInput.value.trim();

  if (username.length < 3) {
    throw new Error("Please enter a username with at least 3 characters.");
  }

  return username;
}

function getPublicKeyOptions(data) {
  // Supports APIs that return { publicKey: {...} } or the options directly.
  return data.publicKey || data;
}

function prepareCreationOptions(data) {
  const publicKey = getPublicKeyOptions(data);

  if (!publicKey.challenge || !publicKey.user?.id) {
    throw new Error(
      "The registration options are missing a challenge or user ID. Check the backend response."
    );
  }

  return {
    ...publicKey,
    challenge: base64urlToBuffer(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: base64urlToBuffer(publicKey.user.id)
    },
    excludeCredentials: (publicKey.excludeCredentials || []).map(item => ({
      ...item,
      id: base64urlToBuffer(item.id)
    }))
  };
}

function prepareRequestOptions(data) {
  const publicKey = getPublicKeyOptions(data);

  if (!publicKey.challenge) {
    throw new Error(
      "The login options are missing a challenge. Check the backend response."
    );
  }

  return {
    ...publicKey,
    challenge: base64urlToBuffer(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map(item => ({
      ...item,
      id: base64urlToBuffer(item.id)
    }))
  };
}

function credentialToJSON(credential) {
  const response = credential.response;
  const result = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {}
  };

  if (response.clientDataJSON) {
    result.response.clientDataJSON =
      bufferToBase64url(response.clientDataJSON);
  }

  if (response.attestationObject) {
    result.response.attestationObject =
      bufferToBase64url(response.attestationObject);
  }

  if (response.authenticatorData) {
    result.response.authenticatorData =
      bufferToBase64url(response.authenticatorData);
  }

  if (response.signature) {
    result.response.signature =
      bufferToBase64url(response.signature);
  }

  if (response.userHandle) {
    result.response.userHandle =
      bufferToBase64url(response.userHandle);
  } else if (response.userHandle === null) {
    result.response.userHandle = null;
  }

  if (typeof response.getTransports === "function") {
    result.response.transports = response.getTransports();
  }

  return result;
}

function setBusy(isBusy) {
  registerBtn.disabled = isBusy;
  loginBtn.disabled = isBusy;
}

async function registerPasskey() {
  const username = getUsername();

  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(
      "Your browser does not support WebAuthn, or this page is not using a secure context. Try http://localhost:8000."
    );
  }

  setStatus("Preparing passkey registration...");

  const optionsData = await postJSON(API.registerOptions, { username });
  const publicKey = prepareCreationOptions(optionsData);

  setStatus("Follow your browser's prompt to create a passkey...");

  const credential = await navigator.credentials.create({ publicKey });

  if (!credential) {
    throw new Error("Passkey registration was cancelled.");
  }

  setStatus("Verifying your new passkey with the server...");

  const result = await postJSON(API.registerVerify, {
    username,
    credential: credentialToJSON(credential)
  });

  setStatus(
    result.message || "Passkey registration completed successfully.",
    "success"
  );
}

async function loginWithPasskey() {
  const username = getUsername();

  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(
      "Your browser does not support WebAuthn, or this page is not using a secure context. Try http://localhost:8000."
    );
  }

  setStatus("Preparing passkey login...");

  const optionsData = await postJSON(API.loginOptions, { username });
  const publicKey = prepareRequestOptions(optionsData);

  setStatus("Follow your browser's prompt to authenticate...");

  const credential = await navigator.credentials.get({ publicKey });

  if (!credential) {
    throw new Error("Passkey login was cancelled.");
  }

  setStatus("Verifying your authentication with the server...");

  const result = await postJSON(API.loginVerify, {
    username,
    credential: credentialToJSON(credential)
  });

  setStatus(
    result.message || "Passkey login completed successfully.",
    "success"
  );
}

async function runAction(action) {
  setBusy(true);

  try {
    await action();
  } catch (error) {
    if (error.name === "NotAllowedError") {
      setStatus(
        "Authentication was cancelled or timed out. Please try again.",
        "error"
      );
    } else {
      setStatus(error.message || "Something went wrong.", "error");
      console.error(error);
    }
  } finally {
    setBusy(false);
  }
}

registerBtn.addEventListener("click", () => {
  runAction(registerPasskey);
});

loginBtn.addEventListener("click", () => {
  runAction(loginWithPasskey);
});
