import { 
  startFetchUser, 
  startFindUser, 
  handleCommentBad,
  handleCommentBad2,
  handleCommentGood,
  createUser as createUserService 
} from "../services/userService.js";

// Route A: complex chain start (sync -> async -> manager -> db)
export async function getUser(req, res) {
  const username = req.params.username; // SOURCE: user-controlled path param
  // Start a long chain: controller -> userService -> asyncForwarder -> managerService -> DB sink
  console.log("DEBUG searching for user:", username);
  const result = await startFetchUser(username);
  res.json({ user: result });
}

// Route B: safe path (proper sanitizer + parameterized safe sink)
export async function searchUser(req, res) {
  const term = req.params.term; // SOURCE
  console.log("DEBUG search term:", term);
  const results = await startFindUser(term);
  res.json({ results });
}

// Route D: intentionally insecure insert user (POST /users)
export async function createUser(req, res) {
  console.log("DEBUG req.body:", req.body);
  const { username, email } = req.body || {};
  console.log("DEBUG types:", typeof username, typeof email);
  console.log("DEBUG username value:", username);
  // call insecure service which will perform concatenated INSERT
  await createUserService(username, email);
  res.json({ ok: true });
}

// Route C1: XSS test — BAD (unsafe) path
// post body: { comment: "..." }
export async function postCommentBad(req, res) {
  const comment = req.body.comment;
  console.log("DEBUG bad comment:", comment);

  const badHtml = await handleCommentBad(comment);
  res.setHeader("Content-Type", "text/html");
  res.send(badHtml); // intentionally tainted
}

export async function postCommentBad2(req, res) {
  const comment = req.body.comment;
  console.log("DEBUG bad2 comment:", comment);

  const badHtml = await handleCommentBad2(comment);
  res.setHeader("Content-Type", "text/html");
  res.send(badHtml); // intentionally tainted
}

// Route C2: XSS test — GOOD (safe) path
// post body: { comment: "..." }
export async function postCommentGood(req, res) {
  const comment = req.body.comment;
  console.log("DEBUG good comment:", comment);

  const goodHtml = await handleCommentGood(comment);
  res.setHeader("Content-Type", "text/html");
  res.send(goodHtml);
}