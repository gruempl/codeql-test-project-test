# Sample NodeJS REST API project for testing CodeQL dataflow analysis

This project is a **Node.js / Express REST API** built to test how **CodeQL** handles complex, multi-file, multi-hop **data-flow analysis** in JavaScript.

It intentionally mixes:

* Reachable and unreachable (dead) insecure code,
* Proper and improper input sanitization,
* Multiple vulnerability types — **SQL Injection** and **Cross-Site Scripting (XSS)**,
* Inter-procedural and asynchronous propagation.

---

## 🧠 Goal

To see whether CodeQL:

1. Correctly reports *only* insecure flows that are actually reachable (from a real user input source to a dangerous sink).
2. Ignores **dead**, **unused**, or **unreachable** insecure code.
3. Properly distinguishes between *unsafe*, *improperly sanitized*, and *properly sanitized* data.

---

## ⚙️ Setup

### Install dependencies

```bash
npm install
```

### Start MySQL quickly with Docker or Podman

If you have Docker Desktop or Podman available, you can spin up a lightweight MySQL container instantly:

#### Using Docker

```bash
docker run --name mysql-test -e MYSQL_ROOT_PASSWORD=root -p 3306:3306 -d mysql:8
docker exec -it mysql-test mysql -uroot -proot -e "CREATE DATABASE IF NOT EXISTS test;"
```

#### Using Podman

```bash
podman run --name mysql-test -e MYSQL_ROOT_PASSWORD=root -p 3306:3306 -d docker.io/library/mysql:8
podman exec -it mysql-test mysql -uroot -proot -e "CREATE DATABASE IF NOT EXISTS test;"
```

### Create database and tables

```sql
CREATE DATABASE IF NOT EXISTS test;
USE test;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255),
  email VARCHAR(255)
);
```

### Run the server

```bash
npm start
```

The API runs on:
👉 **[http://localhost:3000/api/users](http://localhost:3000/api/users)**

### Analyze with CodeQL

```bash
codeql database create codeql-db --language=javascript --source-root=.
codeql database analyze codeql-db codeql/javascript-queries.qls \
  --format=sarifv2.1.0 --output=results.sarif
```

---

## 🔍 Sources and Sinks Overview

| #     | Category                        | Source                                                   | Sink                       | Sanitizer              | Reachable? | Expected CodeQL Behavior                                                    |
| ----- | ------------------------------- | -------------------------------------------------------- | -------------------------- | ---------------------- | ---------- | --------------------------------------------------------------------------- |
| **1** | SQL Injection (unsafe)          | `req.params.username` in `GET /api/users/name/:username` | `unsafeQueryWithConcat()`  | None                   | ✅ Yes      | **Should be detected** — untrusted user input flows into SQL concatenation. |
| **2** | SQL Injection (safe)            | `req.params.term` in `GET /api/users/search/:term`       | `safeParameterizedQuery()` | ✅ `goodSanitizeSQL()`  | ✅ Yes      | **Should NOT be detected** — properly sanitized + parameterized.            |
| **3** | XSS (unsafe)                    | `req.body.comment` in `POST /api/users/comment/bad`      | `xssBadSink()`             | ⚠️ `badSanitizeHTML()` | ✅ Yes      | **Should be detected** — tainted HTML rendered without escaping.            |
| **4** | XSS (safe)                      | `req.body.comment` in `POST /api/users/comment/good`     | `xssSafeSink()`            | ✅ `goodSanitizeHTML()` | ✅ Yes      | **Should NOT be detected** — safely escaped.                                |
| **5** | SQL Injection (unsafe insert)   | `req.body.username` in `POST /api/users`                 | `insertUser()`             | None                   | ✅ Yes      | **Should be detected** — SQL concatenation in `INSERT` statement.           |
| **6** | SQL Injection (dead path)       | `req.params.id` in `/admin/delete/:id`                   | `deleteUser()`             | ⚠️ `badSanitizeSQL()`  | ❌ No       | **Should NOT be detected** — route never mounted.                           |
| **7** | SQL Injection (dead service fn) | `deadPath()` in `userService.js`                         | `deleteUser()`             | ⚠️ `badSanitizeSQL()`  | ❌ No       | **Should NOT be detected** — function never called.                         |

**Note on dead/unused sanitizer functions:**
This repository also contains intentionally insecure sanitizer variants that are **not** used by any mounted route (they are present to test whether static analysis incorrectly flags unused helpers). Examples include:

* `badSanitizeHTML2` — a second, naive HTML sanitizer variant (removes `<script>` and attempts to strip `on*` attributes).
* `badSanitizeSQL2` — a naive SQL sanitizer variant that strips quotes, semicolons and common SQL keywords.

These functions are included deliberately and are **dead / unreferenced** by any reachable route. **CodeQL should not report findings that only flow through these dead sanitizer functions**, since they are not reachable from an HTTP source.

---

## 🧬 Dataflow Breakdown

### Example 1 — SQL Injection (GET /api/users/name/:username)

```text
req.params.username
↓
userController.getUser()
↓
userService.startFetchUser()
↓
utils.forwarder.forwardViaAsync()
↓
asyncForwarder.forwardToAsync()
↓
managerService.managerProcess()
↓
db.insecureQueries.unsafeQueryWithConcat()  ← SINK
```

✅ **Detected (CWE-89)**

---

### Example 2 — SQL Injection (POST /api/users)

```text
req.body.username, req.body.email
↓
userController.createUser()
↓
userService.createUser()
↓
db.insecureQueries.insertUser()  ← SINK
```

✅ **Detected (CWE-89)** — intentionally insecure `INSERT` with string concatenation.

---

### Example 3 — SQL Injection (Safe)

```text
req.params.term
↓
userController.searchUser()
↓
userService.startFindUser()
↓
managerService.managerProcess({ secure: true })
↓
db.secureQueries.safeParameterizedQuery()  ← SAFE SINK
```

❌ **Not detected**

---

### Example 4 — XSS (Unsafe)

```text
req.body.comment
↓
userController.postCommentBad()
↓
badSanitizeHTML()
↓
managerService.managerProcess({ xssBad: true })
↓
db.xssSinks.xssBadSink()  ← SINK
```

✅ **Detected (CWE-79)**

---

### Example 5 — Dead Sink

```text
/admin/delete/:id  (unmounted)
↓
routes.registerDeadRoute()
↓
db.insecureQueries.deleteUser()  ← DEAD SINK
```

❌ **Not detected**

---

## 🧪 Testing the endpoints

```bash
# 1️⃣ Vulnerable SELECT via path param
curl "http://localhost:3000/api/users/name/alice"
curl "http://localhost:3000/api/users/name/alice'%20OR%20'1'='1"
curl "http://localhost:3000/api/users/name/alice'%20OR%20%271%27=%271"
curl "http://localhost:3000/api/users/name/alice'--"
curl "http://localhost:3000/api/users/name/alice'%20OR%20IF(SLEEP(3),1,1)--"


# 2️⃣ Safe search (parameterized)
curl "http://localhost:3000/api/users/search/alice"

# 3️⃣ Safe & Unsafe XSS ((im)proper sanitization)
curl -X POST http://localhost:3000/api/users/comment/good \
  -H "Content-Type: application/json" \
  -d @xx_payload.json

curl -X POST http://localhost:3000/api/users/comment/bad \
  -H "Content-Type: application/json" \
  -d @xx_payload_img.json

# Example payload files:
# xx_payload.json:
#   {"comment": "<script>alert(0)</script>"}
# xx_payload_img.json:
#   {"comment": "<img src=x onerror=\"alert('xss2')\">"}

# 4️⃣ Insecure INSERT (SQL injection demo)
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"email\":\"alice@example.com\"}"

curl -v -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice'); -- \",\"email\":\"x@x.com\"}"

curl -v -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice'); SELECT IF(SLEEP(3),1,1); -- \",\"email\":\"a@b.com\"}"
```

---

## ✅ Expected CodeQL Findings

| CWE    | Type            | Location                                  | Expected  |
| ------ | --------------- | ----------------------------------------- | --------- |
| CWE-89 | SQL Injection   | `unsafeQueryWithConcat()`                 | ✅ Flagged |
| CWE-89 | SQL Injection   | `insertUser()`                            | ✅ Flagged |
| CWE-79 | XSS             | `xssBadSink()`                            | ✅ Flagged |
| —      | Safe query      | `safeParameterizedQuery()`                | ❌ Ignored |
| —      | Safe XSS        | `xssSafeSink()`                           | ❌ Ignored |
| —      | Dead sanitizers | `badSanitizeHTML2()`, `badSanitizeSQL2()` | ❌ Ignored |
| —      | Dead routes     | `deleteUser()` / `deadPath()`             | ❌ Ignored |

---

### 🧩 Author’s note

This project is intentionally designed for **CodeQL taint-tracking validation**.
It demonstrates deep propagation across async, multi-module chains and includes realistic dead/unreachable code for precision testing.
