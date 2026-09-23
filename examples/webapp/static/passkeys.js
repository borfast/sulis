// passkeys.js drives the three WebAuthn flows this example exposes:
// registering a new passkey (on /security), signing in with a known email
// (on /login), and usernameless sign-in (also on /login). It only wires up
// whichever buttons are actually present on the current page, so this one
// file can be included from both templates.
//
// Every fetch() call below sends the page's CSRF token in the X-CSRF-Token
// header, which sulis.VerifyCSRFToken checks before it falls back to a form
// field: these endpoints are JSON, not <form> posts, so the header is the
// only place to put the token.

// base64UrlToBytes decodes a base64url string (no padding, "-"/"_" instead
// of "+"/"/") into a Uint8Array, the encoding every challenge and
// credential ID field arrives in from the server.
function base64UrlToBytes(value) {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/");
	const padLength = padded.length % 4 === 0 ? 0 : 4 - (padded.length % 4);
	const binary = atob(padded + "=".repeat(padLength));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

// bytesToBase64Url encodes an ArrayBuffer the same way the server expects
// it back: base64url, no padding.
function bytesToBase64Url(buffer) {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// decodeCreationOptions converts the JSON credential creation options the
// server sends into the shape navigator.credentials.create() expects:
// challenge, user.id, and every excludeCredentials[].id as ArrayBuffers
// rather than base64url strings.
function decodeCreationOptions(creation) {
	const publicKey = creation.publicKey;
	publicKey.challenge = base64UrlToBytes(publicKey.challenge);
	publicKey.user.id = base64UrlToBytes(publicKey.user.id);
	if (publicKey.excludeCredentials) {
		publicKey.excludeCredentials = publicKey.excludeCredentials.map(function (cred) {
			return Object.assign({}, cred, { id: base64UrlToBytes(cred.id) });
		});
	}
	return publicKey;
}

// decodeRequestOptions does the same conversion for a login assertion's
// options: challenge and every allowCredentials[].id.
function decodeRequestOptions(assertion) {
	const publicKey = assertion.publicKey;
	publicKey.challenge = base64UrlToBytes(publicKey.challenge);
	if (publicKey.allowCredentials) {
		publicKey.allowCredentials = publicKey.allowCredentials.map(function (cred) {
			return Object.assign({}, cred, { id: base64UrlToBytes(cred.id) });
		});
	}
	return publicKey;
}

// encodeAttestationResponse converts a freshly created PublicKeyCredential
// (from navigator.credentials.create()) into the JSON shape the server's
// FinishRegistrationResponse expects.
function encodeAttestationResponse(credential) {
	return {
		id: credential.id,
		rawId: bytesToBase64Url(credential.rawId),
		type: credential.type,
		response: {
			clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
			attestationObject: bytesToBase64Url(credential.response.attestationObject),
		},
	};
}

// encodeAssertionResponse does the same for a login assertion (from
// navigator.credentials.get()), for FinishLoginResponse and
// FinishDiscoverableLoginResponse.
function encodeAssertionResponse(credential) {
	const response = {
		id: credential.id,
		rawId: bytesToBase64Url(credential.rawId),
		type: credential.type,
		response: {
			clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
			authenticatorData: bytesToBase64Url(credential.response.authenticatorData),
			signature: bytesToBase64Url(credential.response.signature),
		},
	};
	if (credential.response.userHandle) {
		response.response.userHandle = bytesToBase64Url(credential.response.userHandle);
	}
	return response;
}

// postJSON sends body as JSON to path with the given CSRF token, and
// returns the parsed JSON response either way: the server's error
// responses are JSON too, shaped as {"error": "..."}.
async function postJSON(path, csrfToken, body) {
	const res = await fetch(path, {
		method: "POST",
		headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
		body: JSON.stringify(body || {}),
		credentials: "same-origin",
	});
	let data = {};
	try {
		data = await res.json();
	} catch (parseErr) {
		// A non-JSON response is itself the failure signal below.
	}
	if (!res.ok) {
		throw new Error(data.error || "Something went wrong.");
	}
	return data;
}

function setStatus(el, message) {
	if (el) {
		el.textContent = message;
	}
}

async function registerPasskey(button, statusEl) {
	const csrfToken = button.dataset.csrf;
	setStatus(statusEl, "Registering...");
	try {
		const creation = await postJSON("/api/passkeys/register/begin", csrfToken, {});
		const publicKey = decodeCreationOptions(creation);
		const credential = await navigator.credentials.create({ publicKey: publicKey });
		const result = await postJSON(
			"/api/passkeys/register/finish",
			csrfToken,
			encodeAttestationResponse(credential),
		);
		window.location.href = result.redirect || "/security";
	} catch (err) {
		setStatus(statusEl, err.message || "Could not register that passkey.");
	}
}

async function loginWithEmail(button, statusEl) {
	const csrfToken = button.dataset.csrf;
	const emailInput = document.getElementById("login-email");
	const email = emailInput ? emailInput.value : "";
	setStatus(statusEl, "Signing in...");
	try {
		const assertion = await postJSON("/api/passkeys/login/begin", csrfToken, { email: email });
		const publicKey = decodeRequestOptions(assertion);
		const credential = await navigator.credentials.get({ publicKey: publicKey });
		const result = await postJSON(
			"/api/passkeys/login/finish",
			csrfToken,
			encodeAssertionResponse(credential),
		);
		window.location.href = result.redirect || "/account";
	} catch (err) {
		setStatus(statusEl, err.message || "Could not sign in.");
	}
}

async function loginUsernameless(button, statusEl) {
	const csrfToken = button.dataset.csrf;
	setStatus(statusEl, "Signing in...");
	try {
		const assertion = await postJSON("/api/passkeys/discoverable/begin", csrfToken, {});
		const publicKey = decodeRequestOptions(assertion);
		const credential = await navigator.credentials.get({ publicKey: publicKey });
		const result = await postJSON(
			"/api/passkeys/discoverable/finish",
			csrfToken,
			encodeAssertionResponse(credential),
		);
		window.location.href = result.redirect || "/account";
	} catch (err) {
		setStatus(statusEl, err.message || "Could not sign in.");
	}
}

document.addEventListener("DOMContentLoaded", function () {
	const registerBtn = document.getElementById("passkey-register-btn");
	if (registerBtn) {
		const statusEl = document.getElementById("passkey-register-status");
		registerBtn.addEventListener("click", function () {
			registerPasskey(registerBtn, statusEl);
		});
	}

	const loginStatusEl = document.getElementById("passkey-login-status");

	const loginBtn = document.getElementById("passkey-login-btn");
	if (loginBtn) {
		loginBtn.addEventListener("click", function () {
			loginWithEmail(loginBtn, loginStatusEl);
		});
	}

	const discoverableBtn = document.getElementById("passkey-discoverable-btn");
	if (discoverableBtn) {
		discoverableBtn.addEventListener("click", function () {
			loginUsernameless(discoverableBtn, loginStatusEl);
		});
	}
});
