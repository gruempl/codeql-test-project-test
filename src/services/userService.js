import { forwardViaAsync } from "../utils/forwarder.js";
import { managerProcess } from "./managerService.js";
import { unsafeQueryWithConcat, deleteUser as deadDeleteUser } from "../db/insecureQueries.js";
import { safeParameterizedQuery } from "../db/secureQueries.js";
import { badSanitizeSQL, goodSanitizeSQL, badSanitizeHTML, goodSanitizeHTML } from "../utils/sanitizer.js";
import { xssBadSink, xssSafeSink } from "../db/xssSinks.js";
import { insertUser } from "../db/insecureQueries.js";

// START for SQL: long chain that uses async hop
export async function startFetchUser(username) {
  // hop 1: naive pass-through
  const step1 = username;
  // hop 2: bad sanitize attempt but we will *not* use it here (to keep sink unsafe)
  const bad = badSanitizeSQL(step1);
  // hop 3: forward to async function (introduces async boundary)
  return forwardViaAsync(step1); // ultimately will reach insecure sink via managerService
}

// START for SEARCH: sanitized + parameterized
export async function startFindUser(term) {
  const trimmed = term.trim();
  const clean = goodSanitizeSQL(trimmed);
  // multiple hops: service -> manager -> secureQuery
  return managerProcess(clean, { secure: true });
}

// Service function to create a user (intentionally insecure)
export async function createUser(username, email) {
  // direct call to insecure DB sink
  return insertUser(username, email);
}


// BAD path — improper HTML sanitization
export async function handleCommentBad(comment) {
  // simulate a broken sanitization (doesn't escape HTML)
  const bad = badSanitizeHTML(comment);

  // route through managerProcess for deeper dataflow
  await managerProcess(bad, { xssBad: true });

  // Return unsanitized HTML string (XSS sink)
  return `<div>${bad}</div>`; // intentionally unsafe
}

// BAD path — improper HTML sanitization
export async function handleCommentBad2(comment) {
  // simulate a broken sanitization (doesn't escape HTML)
  const bad = badSanitizeHTML(comment);

  // Explicitly call the bad sink here so SAST can directly see a source->sink flow.
  // managerProcess still called for the multi-hop chain we want to keep.
  const sinkResult = xssBadSink(bad); // direct call — explicit sink

  // Return unsanitized HTML string (XSS sink)
  return `<div>${sinkResult}</div>`; // intentionally unsafe
}

// GOOD path — proper HTML sanitization
export async function handleCommentGood(comment) {
  // sanitize properly before rendering
  const clean = goodSanitizeHTML(comment);

  // safe managerProcess path
  await managerProcess(clean, { xssSafe: true });

  // Return safely escaped HTML (safe sink)
  return `<div>${clean}</div>`;
}

// Dead function: will never be called by routed code, only left to create a dead sink
export async function deadPath(id) {
  const cleaned = badSanitizeSQL(id);
  // this calls a dead delete in insecureQueries.js
  return deadDeleteUser(cleaned); // dead sink
}
