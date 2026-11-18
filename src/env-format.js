import { validKey } from "./security.js";
// A bounded, non-executing dotenv subset. Export uses JSON-compatible double quotes.
export function parseEnv(input) {
  if (typeof input !== "string" || Buffer.byteLength(input) > 256 * 1024)
    throw new Error("Environment file exceeds 256 KiB.");
  const text = input.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  const result = Object.create(null);
  let position = 0;
  while (position < text.length) {
    while (/[ \t\n]/.test(text[position] || "\0")) position++;
    if (position >= text.length) break;
    if (text[position] === "#") {
      while (position < text.length && text[position] !== "\n") position++;
      continue;
    }
    const match =
      /^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*/.exec(
        text.slice(position),
      );
    if (!match || !validKey(match[1]))
      throw new Error("Invalid environment assignment.");
    const key = match[1];
    position += match[0].length;
    if (Object.hasOwn(result, key))
      throw new Error("Duplicate environment key.");
    let value = "",
      quote = text[position];
    if (quote === "'" || quote === '"' || quote === "`") {
      position++;
      let closed = false;
      while (position < text.length) {
        let char = text[position++];
        if (char === quote) {
          closed = true;
          break;
        }
        if (char === "\\" && quote === '"') {
          if (position >= text.length) throw new Error("Incomplete escape.");
          const next = text[position++];
          const replacements = {
            n: "\n",
            r: "\r",
            t: "\t",
            "\\": "\\",
            '"': '"',
          };
          char = Object.hasOwn(replacements, next)
            ? replacements[next]
            : "\\" + next;
        }
        value += char;
      }
      if (!closed) throw new Error("Unterminated quoted environment value.");
      while (text[position] === " " || text[position] === "\t") position++;
      if (text[position] === "#")
        while (position < text.length && text[position] !== "\n") position++;
      if (position < text.length && text[position] !== "\n")
        throw new Error("Unexpected text after quoted value.");
    } else {
      const start = position;
      while (
        position < text.length &&
        text[position] !== "\n" &&
        text[position] !== "#"
      )
        position++;
      value = text.slice(start, position).trim();
      if (text[position] === "#")
        while (position < text.length && text[position] !== "\n") position++;
    }
    if (Buffer.byteLength(value) > 65536 || value.includes("\0"))
      throw new Error("Invalid or oversized secret value.");
    result[key] = value;
    if (Object.keys(result).length > 500)
      throw new Error("Import is limited to 500 secrets.");
  }
  return result;
}
export function formatEnv(values) {
  return (
    Object.entries(values)
      .map(([key, value]) => {
        if (!validKey(key)) throw new Error("Invalid environment key.");
        return `${key}=${JSON.stringify(value)}`;
      })
      .join("\n") + "\n"
  );
}
