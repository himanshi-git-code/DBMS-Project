# 🛡️ CIMS — Cybersecurity Incident Management System

A web-based Cybersecurity Incident Management System built for the **Database Management System (DBMS)** course at BML Munjal University.

@2026

The idea was to create a system where a security team can track and manage cybersecurity incidents. The system lets users log incidents, link them to affected assets, track which vulnerabilities and threat actors were involved, and monitor response actions taken. There's also a dashboard that gives a quick overview of open incidents, severity distribution, and recent activity.

We built the frontend using **HTML, CSS, and JavaScript**, and the backend as a **PHP REST API** connected to a **MySQL** database.

---

## ⚙️ SQL Features Used

| Feature | Details |
|--------|---------|
| 👁️ **Views** | `vw_incident_summary`, `vw_asset_owner`, `vw_response_detail`, `vw_critical_open` |
| 🔧 **Stored Procedures** | `sp_add_incident`, `sp_get_incidents`, `sp_dashboard_stats` |
| ⚡ **Trigger** | `update_version` fires on every `UPDATE Incidents` — auto-increments version |
| 🔒 **Transactions** | Used in `sp_add_incident` for atomic multi-table inserts |
| 🔁 **Optimistic Locking** | PUT /incidents checks `version` before updating |
| 🗑️ **Cascade Deletes** | Deleting incident removes junction table rows automatically |
| 📌 **Indexes** | `idx_incident_severity`, `idx_incident_status`, `idx_asset_type`, etc. |

---

## 🚀 How to Run

To run this project locally, we used **XAMPP** — a free tool that sets up Apache and MySQL on your Windows machine without any manual configuration.

**1️⃣ Install XAMPP**

We downloaded and installed XAMPP from [apachefriends.org](https://www.apachefriends.org/). Once installed, we opened the **XAMPP Control Panel** and clicked **Start** next to both **Apache** and **MySQL** — Apache serves our PHP files, MySQL runs the database.

**2️⃣ Place the Project Files**

We copied the `cims/` folder into XAMPP's `htdocs` directory:
```
C:/xampp/htdocs/cims/
```
`htdocs` is the root folder that Apache serves — anything placed here becomes accessible via `http://localhost/`.

**3️⃣ Set Up the Database**

We opened `http://localhost/phpmyadmin` in the browser — phpMyAdmin is MySQL's visual interface that comes bundled with XAMPP. We created a new database named `DBMS_project` and ran our SQL script to generate all tables, views, stored procedures, triggers, and sample data.

**4️⃣ Configure DB Connection**

We updated `includes/db.php` with the database credentials. XAMPP's default MySQL setup uses `root` as the username and an empty password, so no changes were needed there.

**5️⃣ Open in Browser**

We opened `http://localhost/cims/` in the browser — the frontend loaded through Apache and all API calls connected to MySQL in the background.
