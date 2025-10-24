// SQL sanitizers

// BAD SQL sanitizer — naive removal of quotes only (improper)
export function badSanitizeSQL(input) {
  if (typeof input !== "string") return input;
  // tries to remove quotes but leaves other SQL meta-chars
  return input.replace(/['"]/g, "");
}

// === badSanitizeSQL2 ===
// BAD SQL sanitizer - naive keyword-stripper + quote removal
// This function attempts to "sanitize" SQL input by removing quotes, semicolons,
// and bluntly stripping common SQL keywords such as UNION, SELECT, OR, etc.
// This is insecure: it can be bypassed easily (encoding, casing, whitespace, alternate syntax),
// and leaves the data vulnerable to SQL injection when concatenated into queries.
export function badSanitizeSQL2(input) {
  if (typeof input !== "string") return input;

  let s = input;

  // 1) Remove single & double quotes (naive)
  s = s.replace(/['"]/g, "");

  // 2) Remove semicolons (naive)
  s = s.replace(/;/g, "");

  // 3) Remove common SQL keywords (naive). This includes "UNION", "SELECT", "INSERT",
  //    "DELETE", "UPDATE", "DROP", "OR", "AND". This is *not* a safe approach — it's
  //    intentionally simplistic so static analyzers like CodeQL can match the pattern.
  s = s.replace(/\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|OR|AND|WHERE|FROM)\b/gi, "");

  // 4) Trim whitespace left by removals
  s = s.replace(/\s+/g, " ").trim();

  return s;
}

// GOOD SQL sanitizer — placeholder that indicates parameterization will be used
export function goodSanitizeSQL(input) {
  // in real world you'd use parameterization; here we just trim to model that input was 'sanitized'
  return input.trim();
}

// HTML sanitizers

// BAD HTML sanitizer — naive replace that fails to remove nested tags or attributes
export function badSanitizeHTML(input) {
  if (typeof input !== "string") return input;
  // remove <script> tags only in a naive way
  return input.replace(/<script.*?>.*?<\/script>/gi, "");
}

// Naive "sanitizer" variant 2 — insecure
// Removes <script>...</script> blocks and attempts to strip on* event handler attributes.
// This is intentionally imperfect and should NOT be used in production.
export function badSanitizeHTML2(input) {
  if (input === undefined || input === null) return input;

  // Ensure we operate on a string
  let s = String(input);

  // 1) Remove script blocks (naive)
  //    This will remove simple <script>...</script> occurrences but can be bypassed by obfuscation.
  s = s.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");

  // 2) Attempt to remove inline event handler attributes like onerror, onclick, onload, etc.
  //    This regex looks for attributes that start with "on" and removes them.
  //    It's intentionally naive: it fails on many obfuscations (mixed case, whitespace tricks, html entities).
  s = s.replace(/\son[A-Za-z0-9\-]*\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");

  // 3) Also remove javascript: scheme in href/src attributes (naive)
  //    This removes "javascript:" from href/src values but may break legitimate content and is bypassable.
  s = s.replace(/(href|src)\s*=\s*(['"]?)\s*javascript\s*:/gi, "$1=$2");

  return s;
}


// GOOD HTML sanitizer — placeholder for proper sanitizer (e.g., DOMPurify) or escaping
export function goodSanitizeHTML(input) {
  // simulate escaping of < and > and quotes
  return String(input)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
