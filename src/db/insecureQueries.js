// Insecure SQL sinks (vulnerable because they concatenate user input)

// add near top
import mysql from "mysql2/promise";
// create connection once (for demo purposes)
const connPromise = mysql.createConnection({ 
  host: 'localhost', 
  user: 'root', 
  password: 'root', 
  database: 'test' });

// Reachable insecure concatenation sink (should be caught)
export async function unsafeQueryWithConcat(userInput) {
  const query = `SELECT * FROM users WHERE username = '${userInput}'`;
  // execute the query (unsafe)
  const conn = await connPromise;
  const [rows] = await conn.query(query); // <-- CodeQL will treat this as SQL sink
  return rows;
}

// Another reachable sink using LIKE with user input (bad sanitize keeps it vulnerable)
export async function unsafeQueryLike(userInput) {
  const query = `SELECT * FROM users WHERE username LIKE '%${userInput}%'`;
  const conn = await connPromise;
  const [rows] = await conn.query(query); // SQL injection sink
  return rows;
}

// Dead sink — delete operation that should be unreachable in normal routes
export async function deleteUser(id) {
  const query = `DELETE FROM users WHERE id = '${id}'`;
  const conn = await connPromise;
  await conn.query(query);
  return [];
}

// Intentionally insecure INSERT sink (vulnerable to SQL injection)
export async function insertUser(username, email) {
  const u = String(username);
  const e = String(email);
  const query = `INSERT INTO users (username, email) VALUES ('${u}', '${e}')`;
  const conn = await connPromise;
  const [result] = await conn.query(query); // result.affectedRows / result.insertId available
  return [{ insertId: result.insertId }];
}
