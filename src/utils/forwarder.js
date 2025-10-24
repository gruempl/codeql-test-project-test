import { forwardToAsync } from "../async/asyncForwarder.js";

// simple hop that forwards into async boundary
export function forwardViaAsync(value) {
  return forwardToAsync(value); // continues chain (hop 3)
}
