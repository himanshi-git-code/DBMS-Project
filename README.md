# CIMS — Cybersecurity Incident Management System

A full-stack web application for managing cybersecurity incidents, assets, vulnerabilities, 
and threat actors — built with **PHP**, **MySQL**, and **Vanilla JavaScript**.

Developed as a DBMS course project.

---

## Features

- 🔐 **Authentication** — Login & Register with role-based access (Admin / Analyst)
- 🚨 **Incident Management** — Create, update, delete, and filter incidents by severity/status
- 🖥️ **Asset Tracking** — Manage organizational assets and link them to incidents
- ⚠️ **Vulnerability & Threat Monitoring** — Track vulnerabilities and threat actors
- 📊 **Dashboard** — Live stats via stored procedure `sp_dashboard_stats`
- 📜 **System Logs** — Audit trail of all activity
- 🔒 **Optimistic Locking** — Prevents concurrent update conflicts using version field

---

## Tech Stack

| Layer      | Technology          |
|------------|---------------------|
| Frontend   | HTML, CSS, JavaScript |
| Backend    | PHP (REST API)      |
| Database   | MySQL               |
| Server     | Apache via XAMPP    |

---

## SQL Features Used

- **Views** — `vw_incident_summary`, `vw_asset_owner`, `vw_critical_open`, etc.
- **Stored Procedures** — `sp_add_incident`, `sp_get_incidents`, `sp_dashboard_stats`
- **Triggers** — `update_version` auto-increments version on every UPDATE
- **Transactions** — Atomic multi-table inserts in `sp_add_incident`
- **Cascade Deletes** — Junction table rows removed automatically
- **Indexes** — On severity, status, asset type for faster queries

---

## How to Run (XAMPP)

1. **Download & install** [XAMPP](https://www.apachefriends.org/)
2. **Copy project** into `C:/xampp/htdocs/cims/`
3. **Start** Apache and MySQL from XAMPP Control Panel
4. **Open phpMyAdmin** → `http://localhost/phpmyadmin`
5. Create database and run your SQL script:
```sql
   CREATE DATABASE DBMS_project;
   USE DBMS_project;
   -- Run your full SQL file here
```
6. Edit `includes/db.php` with your MySQL credentials (default: root, no password)
7. Open browser → `http://localhost/cims/`

---

## Demo Login Credentials

| Email              | Password | Role    |
|--------------------|----------|---------|
| neha@mail.com      | pass123  | Admin   |
| karan@mail.com     | pass123  | Analyst |
| himanshi@mail.com  | pass123  | Admin   |

---

## Project Structure

```
cims/
├── index.html        ← Main frontend (SPA)
├── style.css         ← Styling
├── script.js         ← All frontend logic
├── includes/
│   └── db.php        ← Database connection config
└── api/
    ├── auth.php      ← Login / Register
    ├── incidents.php ← Incidents CRUD
    ├── assets.php    ← Assets CRUD
    └── data.php      ← Vulnerabilities, Threats, Responses, Logs, Dashboard
```
