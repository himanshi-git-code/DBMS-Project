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

## How to Run

We used **XAMPP** to run this project locally on a Windows machine.

### 1. Install XAMPP
Download and install [XAMPP](https://www.apachefriends.org/) — it gives you Apache (web server)
and MySQL together in one package, no separate setup needed.

### 2. Place the Project Files
Copy the `cims/` folder into XAMPP's `htdocs` directory:
```
C:/xampp/htdocs/cims/
```
This is the folder Apache serves files from — anything placed here is accessible via `localhost`.

### 3. Start Apache and MySQL
Open the **XAMPP Control Panel** and click **Start** next to both **Apache** and **MySQL**.
Apache runs the PHP backend, MySQL runs the database.

### 4. Set Up the Database
Open your browser and go to `http://localhost/phpmyadmin` — this is MySQL's visual interface
that comes bundled with XAMPP. From here:
- Create a new database named `DBMS_project`
- Import/run the SQL script to create all tables, views, stored procedures, triggers, and sample data

### 5. Configure DB Connection
Open `includes/db.php` and set your credentials. By default XAMPP uses:
```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');       // your MySQL username
define('DB_PASS', '');           // your MySQL password (empty by default in XAMPP)
define('DB_NAME', 'DBMS_project');
```

### 6. Open in Browser
Navigate to `http://localhost/cims/` — the app loads from Apache and connects to MySQL in the background.

---


## SQL Features Used

- **Views:** `vw_incident_summary`, `vw_asset_owner`, `vw_response_detail`, `vw_critical_open`
- **Stored Procedures:** `sp_add_incident`, `sp_get_incidents`, `sp_dashboard_stats`
- **Trigger:** `update_version` fires on every `UPDATE Incidents` — auto-increments version
- **Transactions:** Used in `sp_add_incident` for atomic multi-table inserts
- **Optimistic Locking:** PUT /incidents checks `version` before updating
- **Cascade Deletes:** Deleting incident removes junction table rows automatically
- **Indexes:** `idx_incident_severity`, `idx_incident_status`, `idx_asset_type`, etc.
