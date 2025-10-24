import { managerProcess } from "../services/managerService.js";

// async boundary: returns a Promise and awaits manager
export async function forwardToAsync(value) {
  // simulate asynchronous processing and another intermediate hop
  await new Promise((resolve) => setTimeout(resolve, 10)); // async gap
  // Hop: call managerProcess which will call insecure sink
  return managerProcess(value);
}
