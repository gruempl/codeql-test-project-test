// XSS sinks: insecure render (improper escaping) vs safe render (escaped)

// BAD XSS sink: directly places comment into HTML response (vulnerable)
export function xssBadSink(comment) {
  const html = `<div class="comment">${comment}</div>`;
  console.log("[XSS] Rendering insecure HTML:", html);
  return html;
}

// SAFE XSS sink: expects sanitized/escaped input (should not be flagged if input escaped)
export function xssSafeSink(escapedComment) {
  const html = `<div class="comment">${escapedComment}</div>`;
  console.log("[XSS] Rendering safe HTML:", html);
  return html;
}
