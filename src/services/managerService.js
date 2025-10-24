import { unsafeQueryWithConcat, unsafeQueryLike } from "../db/insecureQueries.js";
import { safeParameterizedQuery } from "../db/secureQueries.js";
import { xssBadSink, xssSafeSink } from "../db/xssSinks.js";

// managerProcess centralizes calls — acts as further indirection (hop 4/5)
export async function managerProcess(value, opts = {}) {
  // hop: maybe do more transforms — we keep value as-is for clarity
  const v = value;

  if (opts.secure) {
    // safe parameterized database call (secure sink)
    return safeParameterizedQuery(v);
  }

  if (opts.xssBad) {
    // deliberately call bad XSS sink
    return xssBadSink(v);
  }

  if (opts.xssSafe) {
    return xssSafeSink(v);
  }

  // default: unsafe DB call reachable via long chain
  // simulate some conditional that is true at runtime
  if (v && v.length > 0) {
    // hop: call an insecure concatenation based query (sink)
    return unsafeQueryWithConcat(v);
  } else {
    return [];
  }
}
