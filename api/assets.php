<?php
// api/assets.php — CRUD for Assets
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit;

require_once '../includes/db.php';

$db     = getDB();
$method = $_SERVER['REQUEST_METHOD'];
$body   = getBody();

if ($method === 'GET') {
    $type   = $_GET['type']   ?? '';
    $search = $_GET['search'] ?? '';

    // Uses vw_asset_owner view
    $sql = "SELECT a.asset_id, a.asset_name, a.asset_type, a.ip_address,
                   a.status, a.owner_id, a.created_at,
                   u.name AS owner_name, u.email AS owner_email, u.department
            FROM Assets a
            LEFT JOIN Users u ON a.owner_id = u.user_id
            WHERE 1=1";
    $params = []; $types = '';
    if ($type)   { $sql .= " AND a.asset_type = ?";       $types .= 's'; $params[] = $type; }
    if ($search) { $sql .= " AND a.asset_name LIKE ?";    $types .= 's'; $params[] = "%$search%"; }

    $stmt = $db->prepare($sql);
    if ($types) $stmt->bind_param($types, ...$params);
    $stmt->execute();
    respond($stmt->get_result()->fetch_all(MYSQLI_ASSOC));
}

if ($method === 'POST') {
    $name    = trim($body['asset_name'] ?? '');
    $type    = $body['asset_type']      ?? 'Other';
    $ip      = $body['ip_address']      ?? null;
    $ownerId = $body['owner_id']        ?? null;
    $status  = $body['status']          ?? 'Active';
    if (!$name) respond(['error' => 'Asset name required'], 400);

    $stmt = $db->prepare("INSERT INTO Assets (asset_name, asset_type, ip_address, owner_id) VALUES (?, ?, ?, ?)");
    $stmt->bind_param('sssi', $name, $type, $ip, $ownerId);
    if (!$stmt->execute()) respond(['error' => $stmt->error], 500);
    respond(['success' => true, 'asset_id' => $stmt->insert_id]);
}

if ($method === 'PUT') {
    $id      = $body['asset_id']   ?? null;
    $name    = $body['asset_name'] ?? null;
    $type    = $body['asset_type'] ?? null;
    $ip      = $body['ip_address'] ?? null;
    $status  = $body['status']     ?? null;
    $ownerId = array_key_exists('owner_id', $body) ? $body['owner_id'] : 'SKIP';
    if (!$id) respond(['error' => 'asset_id required'], 400);

    $sets = []; $params = []; $types = '';
    if ($name !== null)   { $sets[] = 'asset_name = ?'; $types .= 's'; $params[] = $name; }
    if ($type !== null)   { $sets[] = 'asset_type = ?'; $types .= 's'; $params[] = $type; }
    if ($ip   !== null)   { $sets[] = 'ip_address = ?'; $types .= 's'; $params[] = $ip; }
    if ($status !== null) { $sets[] = 'status = ?';     $types .= 's'; $params[] = $status; }
    if ($ownerId !== 'SKIP') {
        $sets[] = 'owner_id = ?';
        if ($ownerId === null || $ownerId === '') { $types .= 'i'; $params[] = null; }
        else { $types .= 'i'; $params[] = (int)$ownerId; }
    }

    if (empty($sets)) respond(['error' => 'Nothing to update'], 400);

    $stmt = $db->prepare("UPDATE Assets SET " . implode(', ', $sets) . " WHERE asset_id = ?");
    $types .= 'i'; $params[] = $id;
    $stmt->bind_param($types, ...$params);
    if (!$stmt->execute()) respond(['error' => $stmt->error], 500);
    respond(['success' => true]);
}

if ($method === 'DELETE') {
    $id = $body['asset_id'] ?? $_GET['id'] ?? null;
    if (!$id) respond(['error' => 'asset_id required'], 400);
    // CASCADE deletes: related Incidents and Logs
    $stmt = $db->prepare("DELETE FROM Assets WHERE asset_id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    respond(['success' => true]);
}