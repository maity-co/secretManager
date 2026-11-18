import { validEmail } from "./security.js";

// Exact, ASCII DNS domains only. An empty setting preserves self-hosted defaults.
export function emailDomainPolicy(value = "") {
  if (typeof value !== "string")
    throw new Error("Invalid allowed email domains.");
  const domain =
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const domains =
    value.trim() === ""
      ? []
      : value.split(",").map((part) => part.trim().toLowerCase());
  if (
    domains.length > 10 ||
    domains.some((part) => part.length > 253 || !domain.test(part))
  )
    throw new Error(
      "Use a comma-separated list of exact email domains without @ or wildcards.",
    );
  const allowed = new Set(domains);
  return Object.freeze({
    domains: Object.freeze([...allowed]),
    restricted: allowed.size > 0,
    permits(email) {
      if (typeof email !== "string") return false;
      const normalized = email.trim().toLowerCase();
      return (
        validEmail(normalized) &&
        (!allowed.size || allowed.has(normalized.split("@")[1]))
      );
    },
  });
}
