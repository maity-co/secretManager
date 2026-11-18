export const SESSION_CHANGED_MESSAGE =
  "Your browser session changed or its security token expired. Reload and check the signed-in account before trying again.";

export function createApi({
  fetcher = (...args) => fetch(...args),
  onSessionChanged = () => {},
  onRestricted = () => {},
  onReauthenticationRequired = () => {},
} = {}) {
  let csrf = "";
  let blocked = false;
  return async function api(path, method = "GET", body) {
    if (blocked) throw new Error(SESSION_CHANGED_MESSAGE);
    const response = await fetcher("/api" + path, {
      method,
      credentials: "same-origin",
      headers: {
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        "X-CSRF-Token": csrf,
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const data = response.headers
      .get("content-type")
      ?.includes("application/json")
      ? await response.json()
      : await response.text();
    // Discard responses already in flight when another request detected a mismatch.
    if (blocked) throw new Error(SESSION_CHANGED_MESSAGE);
    if (!response.ok) {
      if (data?.code === "EMAIL_DOMAIN_NOT_ALLOWED") onRestricted();
      if (data?.code === "SESSION_REAUTH_REQUIRED" && csrf)
        onReauthenticationRequired();
      if (
        response.status === 403 &&
        (data?.code === "CSRF_MISMATCH" ||
          data?.error === "CSRF verification failed.")
      ) {
        blocked = true;
        csrf = "";
        onSessionChanged();
        throw new Error(SESSION_CHANGED_MESSAGE);
      }
      throw new Error(data?.error || "Request failed.");
    }
    if (data?.csrf) csrf = data.csrf;
    return data;
  };
}
