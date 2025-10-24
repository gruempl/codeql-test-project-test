import express from "express";
import asyncHandler from "../utils/asyncHandler.js";
import { 
  getUser, 
  searchUser, 
  postCommentBad,
  postCommentBad2,
  postCommentGood,
  createUser 
} from "../controllers/userController.js";


const router = express.Router();

// Route A: SQL injection reachable chain (long multi-hop)
router.get("/name/:username", asyncHandler(getUser));

// Route B: safe search that uses proper HTML + parameterization
router.get("/search/:term", asyncHandler(searchUser));

// Route C: XSS testing — posts comment content (demonstrates proper and improper sanitizers)
// BAD XSS path
router.post("/comment/bad", postCommentBad);

// BAD XSS path 2
router.post("/comment/bad2", postCommentBad2);

// GOOD XSS path
router.post("/comment/good", postCommentGood);


// Route D: intentionally insecure user insert
router.post("/", asyncHandler(createUser));

// A dead route definition, exported but NOT mounted on the app (so dead sink)
export function registerDeadRoute(app) {
  // never called by server.js -> dead/unreachable in normal run
  app.delete("/admin/delete/:id", async (req, res) => {
    // dynamic import leads to dead sink
    const { deleteUser } = await import("../db/insecureQueries.js");
    await deleteUser(req.params.id);
    res.sendStatus(204);
  });
}

export default router;
