# CIMS — Cybersecurity Incident Management System
## PHP + MySQL Setup Guide

---

## Folder Structure

```
cims/
├── index.html          ← Main frontend (your HTML/CSS/JS)
├── style.css           ← Your CSS (paste from original file)
├── includes/
│   └── db.php          ← DB connection config
└── api/
    ├── auth.php        ← Login / Register
    ├── incidents.php   ← Incidents CRUD
    ├── assets.php      ← Assets CRUD
    └── data.php        ← Vulns, Threats, Responses, Logs, Users, Dashboard
```

---

## Step 1 — Run the SQL

1. Open **phpMyAdmin** (or MySQL Workbench / CLI)
2. Create the database and run your SQL file:
   ```sql
   CREATE DATABASE DBMS_project;
   USE DBMS_project;
   -- Then paste/run your full SQL script
   ```
3. This creates all tables, triggers, views, stored procedures, and sample data.

---

## Step 2 — Configure DB Connection

Edit `includes/db.php`:
```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');       // your MySQL username
define('DB_PASS', '');           // your MySQL password
define('DB_NAME', 'DBMS_project');
```

---

## Step 3 — Add Your CSS

Open `index.html` and replace:
```html
<link rel="stylesheet" href="style.css">
```
Or paste your full `<style>` block from the original HTML into `index.html`.

---

## Step 4 — Place in Web Server

**Using XAMPP / WAMP / MAMP:**
- Copy the `cims/` folder into `htdocs/` (XAMPP) or `www/` (WAMP)
- Start Apache + MySQL
- Open browser: `http://localhost/cims/`

**Using VS Code Live Server:**
- Does NOT work for PHP files
- Must use XAMPP/WAMP or PHP CLI:
  ```bash
  cd cims
  php -S localhost:8000
  ```
  Then open `http://localhost:8000`

---

## API Reference

| Method | URL | What it does |
|--------|-----|-------------|
| POST | `api/auth.php` | Login (`action: login`) or Register (`action: register`) |
| GET | `api/incidents.php?severity=Critical&status=Open&search=sql` | Get filtered incidents |
| POST | `api/incidents.php` | Create incident (calls `sp_add_incident`) |
| PUT | `api/incidents.php` | Update incident (uses optimistic locking via `version`) |
| DELETE | `api/incidents.php` | Delete incident (cascades to junction tables) |
| GET | `api/assets.php` | Get assets |
| POST/PUT/DELETE | `api/assets.php` | Asset CRUD |
| GET | `api/data.php?entity=dashboard` | Dashboard stats (calls `sp_dashboard_stats`) |
| GET | `api/data.php?entity=vulnerabilities` | Get vulnerabilities |
| GET | `api/data.php?entity=threats` | Get threat actors |
| GET | `api/data.php?entity=responses` | Get response actions |
| GET | `api/data.php?entity=logs` | Get system logs |
| GET | `api/data.php?entity=users` | Get users |
| POST | `api/data.php` | Create record (pass `entity` in body) |
| PUT | `api/data.php?entity=X` | Update record |
| DELETE | `api/data.php?entity=X` | Delete record |

---

## Login Credentials (from seeded data)

| Email | Password | Role |
|-------|----------|------|
| neha@mail.com | pass123 | Admin |
| karan@mail.com | pass123 | Analyst |
| himanshi@mail.com | pass123 | Admin |

> ⚠️ Passwords in your SQL inserts are plain text. For production, use `password_hash()` in PHP and `password_verify()` on login.

---

## SQL Features Used

- **Views:** `vw_incident_summary`, `vw_asset_owner`, `vw_response_detail`, `vw_critical_open`
- **Stored Procedures:** `sp_add_incident`, `sp_get_incidents`, `sp_dashboard_stats`
- **Trigger:** `update_version` fires on every `UPDATE Incidents` — auto-increments version
- **Transactions:** Used in `sp_add_incident` for atomic multi-table inserts
- **Optimistic Locking:** PUT /incidents checks `version` before updating
- **Cascade Deletes:** Deleting incident removes junction table rows automatically
- **Indexes:** `idx_incident_severity`, `idx_incident_status`, `idx_asset_type`, etc.
