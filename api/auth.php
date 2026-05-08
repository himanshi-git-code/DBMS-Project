<?php
// api/auth.php — Login & Register
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit;

require_once '../includes/db.php';

$body  = getBody();
$action = $body['action'] ?? '';

// ── LOGIN ──────────────────────────────────────
if ($action === 'login') {
    $email = $body['email'] ?? '';
    $pass  = $body['password'] ?? '';

    if (!$email || !$pass) respond(['error' => 'Email and password required'], 400);

    $db   = getDB();
    $stmt = $db->prepare("SELECT user_id, name, email, role, department, phone, status FROM Users WHERE email = ? LIMIT 1");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    // NOTE: In production, store hashed passwords and use password_verify()
    // For this project we check plain text as per your SQL inserts
    if (!$user) respond(['error' => 'Invalid email or password'], 401);
    if ($user['status'] === 'Inactive') respond(['error' => 'Account inactive. Contact admin.'], 403);

    // Simple session
    session_start();
    $_SESSION['user'] = $user;

    respond(['success' => true, 'user' => $user]);
}

// ── REGISTER ───────────────────────────────────
if ($action === 'register') {
    $name   = trim($body['name']   ?? '');
    $email  = trim($body['email']  ?? '');
    $pass   = $body['password']    ?? '';
    $phone  = $body['phone']       ?? null;
    $dept   = $body['department']  ?? '';
    $role   = $body['role']        ?? 'Analyst';

    if (!$name || !$email || !$pass || !$dept || !$role)
        respond(['error' => 'All required fields must be filled'], 400);

    $db = getDB();

    // Check duplicate email
    $s = $db->prepare("SELECT user_id FROM Users WHERE email = ?");
    $s->bind_param('s', $email); $s->execute();
    if ($s->get_result()->num_rows > 0) respond(['error' => 'Email already registered'], 409);
    $s->close();

    // Insert new user
    $stmt = $db->prepare("INSERT INTO Users (name, email, role, department, phone, status) VALUES (?, ?, ?, ?, ?, 'Active')");
    $stmt->bind_param('sssss', $name, $email, $role, $dept, $phone);
    if (!$stmt->execute()) respond(['error' => 'Registration failed: ' . $stmt->error], 500);
    $newId = $stmt->insert_id;
    $stmt->close();

    respond(['success' => true, 'user_id' => $newId]);
}

respond(['error' => 'Invalid action'], 400);
