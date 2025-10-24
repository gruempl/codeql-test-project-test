import express from "express";
import userRoutes from "./routes/userRoutes.js";

const app = express();
app.use(express.json());
app.use("/api/users", userRoutes);

// Error handling middleware (must be after routes)
app.use((err, req, res, next) => {
  console.error("[ERROR] Unhandled error:", err && err.stack ? err.stack : err);
  // Return safe error message to client
  res.status(500).json({ error: "Internal Server Error" });
});

// NOTE: We intentionally do not register the dead route (see routes/userRoutes.js)
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
