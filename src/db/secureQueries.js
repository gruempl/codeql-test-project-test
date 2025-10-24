// Secure sink that simulates parameterized query (should not be flagged)

import mysql from "mysql2/promise";
const connPromise = mysql.createConnection({ 
  host: 'localhost', 
  user: 'root', 
  password: 'root', 
  database: 'test' });

export async function safeParameterizedQuery(param) {
  const conn = await connPromise;
  // parameterized execution (safe)
  const [rows] = await conn.execute("SELECT * FROM users WHERE username = ?", [param]);
  return rows;
}
