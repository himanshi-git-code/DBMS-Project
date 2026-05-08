<?php
// api/data.php — Vulnerabilities, ThreatActors, ResponseActions, Logs, Users
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit;

require_once '../includes/db.php';

$db     = getDB();
$method = $_SERVER['REQUEST_METHOD'];
$body   = getBody();
$entity = $_GET['entity'] ?? $body['entity'] ?? '';

// ─────────────────────────────────────────────
// VULNERABILITIES
// ─────────────────────────────────────────────
if ($entity === 'vulnerabilities') {
    if ($method === 'GET') {
        $risk   = $_GET['risk']   ?? '';
        $search = $_GET['search'] ?? '';
        $sql    = "SELECT * FROM Vulnerabilities WHERE 1=1";
        $p = []; $t = '';
        if ($risk)   { $sql .= " AND risk_level = ?"; $t .= 's'; $p[] = $risk; }
        if ($search) { $sql .= " AND (cve_id LIKE ? OR description LIKE ?)"; $t .= 'ss'; $p[] = "%$search%"; $p[] = "%$search%"; }
        $stmt = $db->prepare($sql);
        if ($t) $stmt->bind_param($t, ...$p);
        $stmt->execute();
        respond($stmt->get_result()->fetch_all(MYSQLI_ASSOC));
    }
    if ($method === 'POST') {
        $cve  = trim($body['cve_id']      ?? '');
        $desc = $body['description']       ?? '';
        $risk = $body['risk_level']        ?? 'Medium';
        $disc = $body['discovered_date']   ?? date('Y-m-d');
        if (!$cve) respond(['error' => 'CVE ID required'], 400);
        $stmt = $db->prepare("INSERT INTO Vulnerabilities (cve_id, description, risk_level, discovered_date) VALUES (?, ?, ?, ?)");
        $stmt->bind_param('ssss', $cve, $desc, $risk, $disc);
        if (!$stmt->execute()) respond(['error' => $stmt->error], 500);
        respond(['success' => true, 'vulnerability_id' => $stmt->insert_id]);
    }
    if ($method === 'PUT') {
        $id   = $body['vulnerability_id'] ?? null;
        $cve  = $body['cve_id']           ?? null;
        $desc = $body['description']       ?? null;
        $risk = $body['risk_level']        ?? null;
        if (!$id) respond(['error' => 'vulnerability_id required'], 400);
        $sets = []; $p = []; $t = '';
        if ($cve)  { $sets[] = 'cve_id = ?';      $t .= 's'; $p[] = $cve; }
        if ($desc) { $sets[] = 'description = ?';  $t .= 's'; $p[] = $desc; }
        if ($risk) { $sets[] = 'risk_level = ?';   $t .= 's'; $p[] = $risk; }
        $stmt = $db->prepare("UPDATE Vulnerabilities SET " . implode(', ', $sets) . " WHERE vulnerability_id = ?");
        $t .= 'i'; $p[] = $id;
        $stmt->bind_param($t, ...$p);
        $stmt->execute();
        respond(['success' => true]);
    }
    if ($method === 'DELETE') {
        $id = $body['vulnerability_id'] ?? $_GET['id'] ?? null;
        // CASCADE deletes: Incident_Vulnerability rows
        $stmt = $db->prepare("DELETE FROM Vulnerabilities WHERE vulnerability_id = ?");
        $stmt->bind_param('i', $id); $stmt->execute();
        respond(['success' => true]);
    }
}

// ─────────────────────────────────────────────
// THREAT ACTORS
// ─────────────────────────────────────────────
if ($entity === 'threats') {
    if ($method === 'GET') {
        respond($db->query("SELECT * FROM Threat_Actors ORDER BY name")->fetch_all(MYSQLI_ASSOC));
    }
    if ($method === 'POST') {
        $name    = trim($body['name']           ?? '');
        $country = $body['origin_country']       ?? null;
        $mot     = $body['motivation']           ?? 'Other';
        if (!$name) respond(['error' => 'Name required'], 400);
        $stmt = $db->prepare("INSERT INTO Threat_Actors (name, origin_country, motivation) VALUES (?, ?, ?)");
        $stmt->bind_param('sss', $name, $country, $mot);
        $stmt->execute();
        respond(['success' => true, 'threat_actor_id' => $stmt->insert_id]);
    }
    if ($method === 'PUT') {
        $id   = $body['threat_actor_id'] ?? null;
        $name = $body['name']            ?? null;
        $mot  = $body['motivation']      ?? null;
        if (!$id) respond(['error' => 'threat_actor_id required'], 400);
        $sets = []; $p = []; $t = '';
        if ($name) { $sets[] = 'name = ?';       $t .= 's'; $p[] = $name; }
        if ($mot)  { $sets[] = 'motivation = ?'; $t .= 's'; $p[] = $mot; }
        $stmt = $db->prepare("UPDATE Threat_Actors SET " . implode(', ', $sets) . " WHERE threat_actor_id = ?");
        $t .= 'i'; $p[] = $id;
        $stmt->bind_param($t, ...$p);
        $stmt->execute();
        respond(['success' => true]);
    }
    if ($method === 'DELETE') {
        $id = $body['threat_actor_id'] ?? $_GET['id'] ?? null;
        // CASCADE: Incident_ThreatActor rows
        $stmt = $db->prepare("DELETE FROM Threat_Actors WHERE threat_actor_id = ?");
        $stmt->bind_param('i', $id); $stmt->execute();
        respond(['success' => true]);
    }
}

// ─────────────────────────────────────────────
// RESPONSE ACTIONS
// ─────────────────────────────────────────────
if ($entity === 'responses') {
    if ($method === 'GET') {
        // Uses vw_response_detail view
        $rows = $db->query("SELECT r.*, i.title AS incident_title, u.name AS performer
                            FROM Response_Actions r
                            LEFT JOIN Incidents i ON r.incident_id = i.incident_id
                            LEFT JOIN Users u ON r.performed_by = u.user_id
                            ORDER BY r.action_date DESC")->fetch_all(MYSQLI_ASSOC);
        respond($rows);
    }
    if ($method === 'POST') {
        $incId  = $body['incident_id']        ?? null;
        $by     = $body['performed_by']        ?? null;
        $desc   = $body['action_description']  ?? '';
        $date   = $body['action_date']         ?? date('Y-m-d');
        $status = $body['status']              ?? 'Pending';
        $pri    = $body['priority']            ?? 'Medium';
        if (!$incId || !$desc) respond(['error' => 'incident_id and description required'], 400);
        $stmt = $db->prepare("INSERT INTO Response_Actions (incident_id, performed_by, action_description, action_date, status, priority) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param('iissss', $incId, $by, $desc, $date, $status, $pri);
        $stmt->execute();
        respond(['success' => true, 'action_id' => $stmt->insert_id]);
    }
    if ($method === 'PUT') {
        $id     = $body['action_id'] ?? null;
        $status = $body['status']    ?? null;
        $pri    = $body['priority']  ?? null;
        if (!$id) respond(['error' => 'action_id required'], 400);
        $sets = []; $p = []; $t = '';
        if ($status) { $sets[] = 'status = ?';   $t .= 's'; $p[] = $status; }
        if ($pri)    { $sets[] = 'priority = ?'; $t .= 's'; $p[] = $pri; }
        $stmt = $db->prepare("UPDATE Response_Actions SET " . implode(', ', $sets) . " WHERE action_id = ?");
        $t .= 'i'; $p[] = $id;
        $stmt->bind_param($t, ...$p);
        $stmt->execute();
        respond(['success' => true]);
    }
    if ($method === 'DELETE') {
        $id = $body['action_id'] ?? $_GET['id'] ?? null;
        $stmt = $db->prepare("DELETE FROM Response_Actions WHERE action_id = ?");
        $stmt->bind_param('i', $id); $stmt->execute();
        respond(['success' => true]);
    }
}

// ─────────────────────────────────────────────
// LOGS
// ─────────────────────────────────────────────
if ($entity === 'logs') {
    if ($method === 'GET') {
        $rows = $db->query("SELECT l.*, a.asset_name, a.ip_address
                            FROM Logs l LEFT JOIN Assets a ON l.asset_id = a.asset_id
                            ORDER BY l.log_time DESC")->fetch_all(MYSQLI_ASSOC);
        respond($rows);
    }
    if ($method === 'POST') {
        $assetId = $body['asset_id']   ?? null;
        $evt     = $body['event_type'] ?? 'Other';
        $status  = $body['status']     ?? 'Info';
        if (!$assetId) respond(['error' => 'asset_id required'], 400);
        $stmt = $db->prepare("INSERT INTO Logs (asset_id, event_type, status) VALUES (?, ?, ?)");
        $stmt->bind_param('iss', $assetId, $evt, $status);
        $stmt->execute();
        respond(['success' => true, 'log_id' => $stmt->insert_id]);
    }
    if ($method === 'PUT') {
        $id      = $body['log_id']     ?? null;
        $assetId = $body['asset_id']   ?? null;
        $evt     = $body['event_type'] ?? null;
        $status  = $body['status']     ?? null;
        if (!$id) respond(['error' => 'log_id required'], 400);
        $sets = []; $p = []; $t = '';
        if ($assetId) { $sets[] = 'asset_id = ?';   $t .= 'i'; $p[] = (int)$assetId; }
        if ($evt)     { $sets[] = 'event_type = ?'; $t .= 's'; $p[] = $evt; }
        if ($status)  { $sets[] = 'status = ?';     $t .= 's'; $p[] = $status; }
        if (empty($sets)) respond(['error' => 'Nothing to update'], 400);
        $stmt = $db->prepare("UPDATE Logs SET " . implode(', ', $sets) . " WHERE log_id = ?");
        $t .= 'i'; $p[] = $id;
        $stmt->bind_param($t, ...$p);
        if (!$stmt->execute()) respond(['error' => $stmt->error], 500);
        respond(['success' => true]);
    }
    if ($method === 'DELETE') {
        $id = $body['log_id'] ?? $_GET['id'] ?? null;
        $stmt = $db->prepare("DELETE FROM Logs WHERE log_id = ?");
        $stmt->bind_param('i', $id); $stmt->execute();
        respond(['success' => true]);
    }
}

// ─────────────────────────────────────────────
// USERS (Admin only)
// ─────────────────────────────────────────────
if ($entity === 'users') {
    if ($method === 'GET') {
        $rows = $db->query("SELECT user_id, name, email, role, department, phone, status, created_at FROM Users ORDER BY created_at DESC")->fetch_all(MYSQLI_ASSOC);
        respond($rows);
    }
    if ($method === 'POST') {
        $name  = trim($body['name']       ?? '');
        $email = trim($body['email']      ?? '');
        $role  = $body['role']            ?? 'Analyst';
        $dept  = $body['department']      ?? '';
        $phone = $body['phone']           ?? null;
        if (!$name || !$email) respond(['error' => 'Name and email required'], 400);
        $stmt = $db->prepare("INSERT INTO Users (name, email, role, department, phone, status) VALUES (?, ?, ?, ?, ?, 'Active')");
        $stmt->bind_param('sssss', $name, $email, $role, $dept, $phone);
        if (!$stmt->execute()) respond(['error' => $stmt->error], 500);
        respond(['success' => true, 'user_id' => $stmt->insert_id]);
    }
    if ($method === 'PUT') {
        $id    = $body['user_id']    ?? null;
        $name  = $body['name']       ?? null;
        $email = $body['email']      ?? null;
        $role  = $body['role']       ?? null;
        $dept  = $body['department'] ?? null;
        $phone = $body['phone_number'] ?? $body['phone'] ?? null;
        $status = $body['status']    ?? null;
        if (!$id) respond(['error' => 'user_id required'], 400);
        $sets = []; $p = []; $t = '';
        if ($name)   { $sets[] = 'name = ?';       $t .= 's'; $p[] = $name; }
        if ($email)  { $sets[] = 'email = ?';      $t .= 's'; $p[] = $email; }
        if ($role)   { $sets[] = 'role = ?';       $t .= 's'; $p[] = $role; }
        if ($dept)   { $sets[] = 'department = ?'; $t .= 's'; $p[] = $dept; }
        if ($phone)  { $sets[] = 'phone = ?';      $t .= 's'; $p[] = $phone; }
        if ($status) { $sets[] = 'status = ?';     $t .= 's'; $p[] = $status; }
        if (empty($sets)) respond(['error' => 'Nothing to update'], 400);
        $stmt = $db->prepare("UPDATE Users SET " . implode(', ', $sets) . " WHERE user_id = ?");
        $t .= 'i'; $p[] = $id;
        $stmt->bind_param($t, ...$p);
        if (!$stmt->execute()) respond(['error' => $stmt->error], 500);
        respond(['success' => true]);
    }
    if ($method === 'DELETE') {
        $id = $body['user_id'] ?? $_GET['id'] ?? null;
        // ON DELETE: owner_id SET NULL in Assets, reported_by SET NULL in Incidents
        $stmt = $db->prepare("DELETE FROM Users WHERE user_id = ?");
        $stmt->bind_param('i', $id); $stmt->execute();
        respond(['success' => true]);
    }
}

// ─────────────────────────────────────────────
// DASHBOARD STATS (uses stored procedure sp_dashboard_stats)
// ─────────────────────────────────────────────
if ($entity === 'dashboard') {
    while ($db->more_results()) { $db->next_result(); }
    $q  = function($sql) use ($db) { $r = $db->query($sql); if (!$r) return []; $d = $r->fetch_all(MYSQLI_ASSOC); $r->free(); return $d; };
    $qv = function($sql) use ($db) { $r = $db->query($sql); if (!$r) return 0;  $row = $r->fetch_assoc(); $r->free(); return $row['c'] ?? 0; };
    $stats = [];
    $stats['total_incidents']       = $qv("SELECT COUNT(*) AS c FROM Incidents");
    $stats['critical_incidents']    = $qv("SELECT COUNT(*) AS c FROM Incidents WHERE severity='Critical'");
    $stats['total_assets']          = $qv("SELECT COUNT(*) AS c FROM Assets");
    $stats['total_vulnerabilities'] = $qv("SELECT COUNT(*) AS c FROM Vulnerabilities");
    $stats['total_threats']         = $qv("SELECT COUNT(*) AS c FROM Threat_Actors");
    $stats['active_users']          = $qv("SELECT COUNT(*) AS c FROM Users");
    $stats['by_severity']           = $q("SELECT severity, COUNT(*) AS total FROM Incidents GROUP BY severity");
    $stats['by_status']             = $q("SELECT status, COUNT(*) AS total FROM Incidents GROUP BY status");
    $stats['recent']                = $q("SELECT incident_id, title, severity, status, detected_date FROM Incidents ORDER BY detected_date DESC LIMIT 6");
    respond($stats);
}

respond(['error' => 'Unknown entity'], 400);