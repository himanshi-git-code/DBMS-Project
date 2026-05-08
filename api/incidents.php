<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit;

require_once '../includes/db.php';

$db     = getDB();
$method = $_SERVER['REQUEST_METHOD'];
$body   = getBody();

if ($method === 'GET') {
    $severity = $_GET['severity'] ?? '';
    $status   = $_GET['status']   ?? '';
    $search   = $_GET['search']   ?? '';

    $sql = "SELECT 
                i.incident_id, i.title, i.description, i.severity, i.status,
                i.detected_date,
                i.category,
                1 AS version,
                a.asset_name, a.ip_address, a.asset_id,
                u.name AS reporter, u.user_id AS reported_by, u.department
            FROM Incidents i
            LEFT JOIN Assets a ON i.asset_id = a.asset_id
            LEFT JOIN Users  u ON i.reported_by = u.user_id
            WHERE 1=1";

    $params = []; $types = '';
    if ($severity) { $sql .= " AND i.severity = ?"; $types .= 's'; $params[] = $severity; }
    if ($status)   { $sql .= " AND i.status = ?";   $types .= 's'; $params[] = $status; }
    if ($search)   { $sql .= " AND i.title LIKE ?";  $types .= 's'; $params[] = "%$search%"; }
    $sql .= " ORDER BY i.detected_date DESC";

    $stmt = $db->prepare($sql);
    if ($types) $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    respond($rows);
}

if ($method === 'POST') {
    $title    = trim($body['title']       ?? '');
    $desc     = trim($body['description'] ?? '');
    $severity = $body['severity']         ?? 'Medium';
    $status   = $body['status']           ?? 'Open';
    $date     = $body['detected_date']    ?? date('Y-m-d');
    $assetId  = $body['asset_id']         ?? null;
    $userId   = $body['reported_by']      ?? null;

    if (!$title) respond(['error' => 'Title is required'], 400);

    $stmt = $db->prepare("INSERT INTO Incidents (title, description, severity, status, detected_date, asset_id, reported_by) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('sssssii', $title, $desc, $severity, $status, $date, $assetId, $userId);
    if (!$stmt->execute()) respond(['error' => 'Insert failed: ' . $stmt->error], 500);
    respond(['success' => true, 'incident_id' => $stmt->insert_id]);
}

if ($method === 'PUT') {
    $id = $body['incident_id'] ?? null;
    if (!$id) respond(['error' => 'incident_id required'], 400);

    $title    = $body['title']       ?? null;
    $desc     = $body['description'] ?? null;
    $severity = $body['severity']    ?? null;
    $status   = $body['status']      ?? null;

    $sets = []; $params = []; $types = '';
    if ($title)    { $sets[] = 'title = ?';       $types .= 's'; $params[] = $title; }
    if ($desc)     { $sets[] = 'description = ?'; $types .= 's'; $params[] = $desc; }
    if ($severity) { $sets[] = 'severity = ?';    $types .= 's'; $params[] = $severity; }
    if ($status)   { $sets[] = 'status = ?';      $types .= 's'; $params[] = $status; }

    if (empty($sets)) respond(['error' => 'Nothing to update'], 400);

    $sql = "UPDATE Incidents SET " . implode(', ', $sets) . " WHERE incident_id = ?";
    $types .= 'i'; $params[] = $id;
    $stmt = $db->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $stmt->close();
    respond(['success' => true, 'message' => 'Incident updated']);
}

if ($method === 'DELETE') {
    $id = $body['incident_id'] ?? $_GET['id'] ?? null;
    if (!$id) respond(['error' => 'incident_id required'], 400);
    $stmt = $db->prepare("DELETE FROM Incidents WHERE incident_id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt->close();
    respond(['success' => true, 'message' => 'Incident deleted']);
}

respond(['error' => 'Method not allowed'], 405);