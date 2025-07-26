<?php
// index.php
// Fully combined file for OshoNet Admin Dashboard, API, and Database Configuration.

// --- 1. Session Start and Database Configuration ---
session_start();

// Database credentials (from db_config.php)
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root'); // Your confirmed username
define('DB_PASSWORD', 'Sam#2911'); // Your confirmed password
define('DB_NAME', 'oshonet'); // Your database name

// Attempt to connect to MySQL database
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if ($mysqli === false) {
    error_log("Database connection failed: " . $mysqli->connect_error);
    // If database connection fails, send JSON error for API calls; otherwise, die for HTML page.
    if (isset($_REQUEST['action'])) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Database connection failed.']);
        exit();
    } else {
        die("ERROR: Could not connect to the database. " . $mysqli->connect_error);
    }
}

// Set character set to UTF-8
$mysqli->set_charset("utf8mb4");

// Function to send JSON response (used by API actions)
function sendJsonResponse($status, $message, $data = []) {
    header('Content-Type: application/json');
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $data));
    exit();
}

// --- 2. Authentication Check & Redirection ---
// If the user is not logged in, redirect to login.php
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: login.php");
    exit;
}

// Get the current user's details from the session (guaranteed to be set if we reach here)
$currentUserId = $_SESSION["id"];
$currentUserRole = $_SESSION["role"];
$currentUsername = $_SESSION["username"];

// Define all possible roles for the sharing dropdown (from dashboard.php)
$allRoles = ['owner', 'dev', 'upper_staff', 'low_staff', 'reception'];

// --- Helper function for role-based access levels ---
function getEffectiveAccessLevels($userRole) {
    $allLevels = ['owner', 'dev', 'upper_staff', 'low_staff', 'reception'];
    $roleHierarchy = [
        'owner' => 0,
        'dev' => 1,
        'upper_staff' => 2,
        'low_staff' => 3,
        'reception' => 4
    ];

    $userRoleRank = $roleHierarchy[$userRole] ?? 99; // Assign a high rank if role not found
    $effectiveLevels = [];

    foreach ($allLevels as $level) {
        $levelRank = $roleHierarchy[$level] ?? 99;

        // Special rule for 'dev' level files: only 'owner' and 'dev' can view them.
        if ($level === 'dev') {
            if ($userRole === 'owner' || $userRole === 'dev') {
                $effectiveLevels[] = $level;
            }
        } else {
            // For other levels, standard hierarchy applies: user can view if their rank is <= level's rank
            if ($userRoleRank <= $levelRank) {
                $effectiveLevels[] = $level;
            }
        }
    }
    return $effectiveLevels;
}

// --- 3. API Logic (from api.php) ---
// This block executes if an 'action' parameter is present, indicating an AJAX API request.
if (isset($_REQUEST['action'])) {
    $action = $_REQUEST['action'] ?? '';

    switch ($action) {
        case 'get_all_websites':
            $searchQuery = $_GET['search'] ?? '';
            $typeFilter = $_GET['type_filter'] ?? 'all';
            $levelFilter = $_GET['level_filter'] ?? 'all';
            $sort = $_GET['sort'] ?? 'name_asc';

            $websites = [];

            $allowedPowerLevelsForCurrentUser = getEffectiveAccessLevels($currentUserRole);

            // Build official websites query
            $official_sql = "SELECT id, name, url, power_level, popularity_score, 'official' AS type, 'System' AS creator_username FROM websites WHERE 1";
            $official_bind_params = [];
            $official_bind_types = "";

            if (!empty($searchQuery)) {
                $official_sql .= " AND (name LIKE ? OR url LIKE ?)";
                $official_bind_params[] = "%" . $searchQuery . "%";
                $official_bind_params[] = "%" . $searchQuery . "%";
                $official_bind_types .= "ss";
            }

            $finalLevelsToQuery = [];
            if ($levelFilter === 'all') {
                $finalLevelsToQuery = $allowedPowerLevelsForCurrentUser;
            } else {
                // If a specific level filter is applied, ensure the user has permission for it
                if (in_array($levelFilter, $allowedPowerLevelsForCurrentUser)) {
                    $finalLevelsToQuery[] = $levelFilter;
                }
            }

            if (!empty($finalLevelsToQuery)) {
                $placeholders = implode(',', array_fill(0, count($finalLevelsToQuery), '?'));
                $official_sql .= " AND power_level IN (" . $placeholders . ")";
                $official_bind_types .= str_repeat('s', count($finalLevelsToQuery));
                $official_bind_params = array_merge($official_bind_params, $finalLevelsToQuery);
            } else {
                // If no levels are allowed (e.g., user tries to filter for 'dev' but is 'reception')
                $official_sql = "SELECT id, name, url, power_level, popularity_score, 'official' AS type, 'System' AS creator_username FROM websites WHERE 0"; // Force no results
            }

            // Add ORDER BY clause for official websites
            switch ($sort) {
                case 'name_asc':
                    $official_sql .= " ORDER BY name ASC";
                    break;
                case 'name_desc':
                    $official_sql .= " ORDER BY name DESC";
                    break;
                case 'popularity_desc':
                    $official_sql .= " ORDER BY popularity_score DESC";
                    break;
            }

            // Prepare and execute official websites query
            $stmt_official = $mysqli->prepare($official_sql);
            if ($stmt_official) {
                if (!empty($official_bind_types)) {
                    $stmt_official->bind_param($official_bind_types, ...$official_bind_params);
                }
                $stmt_official->execute();
                $result_official = $stmt_official->get_result();
                while ($row = $result_official->fetch_assoc()) {
                    $websites[] = $row;
                }
                $stmt_official->close();
            } else {
                error_log("Failed to prepare official_sql: " . $mysqli->error);
            }

            // Fetch user saved pages (logic mostly as in original api.php, ensures user_id matches currentUserId or shared_roles includes currentUserRole)
            $user_pages_sql = "SELECT id, user_id, name, url, is_public, shared_roles, creation_time, deletion_time, source_creator_username, source_page_id, creator_username FROM user_saved_pages WHERE 1";
            $user_pages_params = [];
            $user_pages_types = "";

            if (!empty($searchQuery)) {
                $user_pages_sql .= " AND (name LIKE ? OR url LIKE ?)";
                $user_pages_params[] = "%" . $searchQuery . "%";
                $user_pages_params[] = "%" . $searchQuery . "%";
                $user_pages_types .= "ss";
            }

            if ($typeFilter === 'my_pages') {
                $user_pages_sql .= " AND user_id = ?";
                $user_pages_params[] = $currentUserId;
                $user_pages_types .= "i";
            } elseif ($typeFilter === 'shared_pages') {
                $user_pages_sql .= " AND is_public = 1 AND user_id != ? AND shared_roles LIKE ?";
                $user_pages_params[] = $currentUserId;
                $user_pages_params[] = '%"' . $currentUserRole . '"%';
                $user_pages_types .= "is";
            } elseif ($typeFilter === 'official') {
                $user_pages_sql = "SELECT id, user_id, name, url, is_public, shared_roles, creation_time, deletion_time, source_creator_username, source_page_id, creator_username FROM user_saved_pages WHERE 0";
            } else { // 'all' type filter or not specified
                $user_pages_sql .= " AND (user_id = ? OR (is_public = 1 AND user_id != ? AND shared_roles LIKE ?))";
                $user_pages_params[] = $currentUserId;
                $user_pages_params[] = $currentUserId;
                $user_pages_params[] = '%"' . $currentUserRole . '"%';
                $user_pages_types .= "iis";
            }

            // Add ORDER BY clause for user pages
            switch ($sort) {
                case 'name_asc':
                    $user_pages_sql .= " ORDER BY name ASC";
                    break;
                case 'name_desc':
                    $user_pages_sql .= " ORDER BY name DESC";
                    break;
                case 'popularity_desc':
                    $user_pages_sql .= " ORDER BY name ASC"; // User pages don't have popularity, sort by name
                    break;
            }

            // Prepare and execute user saved pages query
            $stmt_user_pages = $mysqli->prepare($user_pages_sql);
            if ($stmt_user_pages) {
                if (!empty($user_pages_types)) {
                    $stmt_user_pages->bind_param($user_pages_types, ...$user_pages_params);
                }
                $stmt_user_pages->execute();
                $result_user_pages = $stmt_user_pages->get_result();
                while ($row = $result_user_pages->fetch_assoc()) {
                    $row['type'] = ($row['user_id'] == $currentUserId) ? 'my_page' : 'shared_page';
                    $websites[] = $row;
                }
                $stmt_user_pages->close();
            } else {
                error_log("Failed to prepare user_pages_sql: " . $mysqli->error);
            }

            sendJsonResponse('success', 'Websites fetched successfully', ['data' => $websites]);
            break;

        case 'increment_popularity':
            if (!isset($_GET['id'])) {
                sendJsonResponse('error', 'Website ID is required.');
            }
            $websiteId = $_GET['id'];
            $sql = "UPDATE websites SET popularity_score = popularity_score + 1 WHERE id = ?";
            if ($stmt = $mysqli->prepare($sql)) {
                $stmt->bind_param("i", $websiteId);
                if ($stmt->execute()) {
                    sendJsonResponse('success', 'Popularity incremented.');
                } else {
                    sendJsonResponse('error', 'Failed to increment popularity: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;

        case 'create_user_page':
            if (!isset($_POST['name'], $_POST['url'])) { // user_id and creator_username derived from session
                sendJsonResponse('error', 'Missing required fields.');
            }
            $name = $_POST['name'];
            $url = $_POST['url'];
            // Use currentUserId and currentUsername from session
            // Fix for "Argument #4 cannot be passed by reference"
            $isPublic = 0; // Initialize as integer variable
            if (isset($_POST['is_public'])) {
                $isPublic = intval($_POST['is_public']);
            }
            $param_isPublic = $isPublic; // Create a new variable to pass by reference
            $sharedRoles = $_POST['shared_roles'] ?? '[]'; // Should be JSON string
            $deletionTime = !empty($_POST['deletion_time']) ? $_POST['deletion_time'] : null;

            $sql = "INSERT INTO user_saved_pages (user_id, name, url, is_public, shared_roles, creation_time, deletion_time, creator_username) VALUES (?, ?, ?, ?, ?, NOW(), ?, ?)";
            if ($stmt = $mysqli->prepare($sql)) {
                // Corrected type string for $isPublic from 's' to 'i'
                $stmt->bind_param("ississs", $currentUserId, $name, $url, $param_isPublic, $sharedRoles, $deletionTime, $currentUsername); // Use $param_isPublic
                if ($stmt->execute()) {
                    sendJsonResponse('success', 'Page saved successfully!');
                } else {
                    sendJsonResponse('error', 'Failed to save page: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;

        case 'update_user_page':
            if (!isset($_POST['id'], $_POST['name'], $_POST['url'])) {
                sendJsonResponse('error', 'Missing required fields for update.');
            }
            $id = $_POST['id'];
            $name = $_POST['name'];
            $url = $_POST['url'];
            // Fix for "Argument #4 cannot be passed by reference"
            $isPublic = 0; // Initialize as integer variable
            if (isset($_POST['is_public'])) {
                $isPublic = intval($_POST['is_public']);
            }
            $param_isPublic = $isPublic; // Create a new variable to pass by reference
            $sharedRoles = $_POST['shared_roles'] ?? '[]';
            $deletionTime = !empty($_POST['deletion_time']) ? $_POST['deletion_time'] : null;

            // Ensure the user owns this page before updating
            $sql = "UPDATE user_saved_pages SET name = ?, url = ?, is_public = ?, shared_roles = ?, deletion_time = ? WHERE id = ? AND user_id = ?";
            if ($stmt = $mysqli->prepare($sql)) {
                // Corrected type string for $isPublic from 's' to 'i'
                $stmt->bind_param("ssissii", $name, $url, $param_isPublic, $sharedRoles, $deletionTime, $id, $currentUserId); // Use $param_isPublic
                if ($stmt->execute()) {
                    if ($stmt->affected_rows > 0) {
                        sendJsonResponse('success', 'Page updated successfully!');
                    } else {
                        sendJsonResponse('error', 'Page not found or you do not have permission to edit it.');
                    }
                } else {
                    sendJsonResponse('error', 'Failed to update page: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;

        case 'delete_user_page':
            if (!isset($_POST['id'])) {
                sendJsonResponse('error', 'Page ID is required for deletion.');
            }
            $id = $_POST['id'];

            // Ensure the user owns this page before deleting
            $sql = "DELETE FROM user_saved_pages WHERE id = ? AND user_id = ?";
            if ($stmt = $mysqli->prepare($sql)) {
                $stmt->bind_param("ii", $id, $currentUserId);
                if ($stmt->execute()) {
                    if ($stmt->affected_rows > 0) {
                        sendJsonResponse('success', 'Page deleted successfully!');
                    } else {
                        sendJsonResponse('error', 'Page not found or you do not have permission to delete it.');
                    }
                } else {
                    sendJsonResponse('error', 'Failed to delete page: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;

        case 'delete_all_user_pages':
            // Ensure the current user ID is used
            $sql = "DELETE FROM user_saved_pages WHERE user_id = ?";
            if ($stmt = $mysqli->prepare($sql)) {
                $stmt->bind_param("i", $currentUserId);
                if ($stmt->execute()) {
                    sendJsonResponse('success', 'All your saved pages have been deleted.');
                } else {
                    sendJsonResponse('error', 'Failed to delete all pages: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;

        case 'get_notifications':
            // Notifications are essentially shared pages that the current user has not yet "kept" or dismissed.
            // We look for pages where:
            // 1. is_public = 1
            // 2. user_id is NOT the current user's ID (i.e., someone else shared it)
            // 3. The current user's role is in the shared_roles list
            // 4. The page has not been dismissed by this user (check notifications_dismissed table)
            // 5. The page has not been kept by this user (check user_saved_pages where source_page_id matches and user_id matches)

            $sql = "SELECT usp.id, usp.name, usp.url, usp.creator_username, usp.creation_time, usp.source_creator_username, usp.source_page_id
                    FROM user_saved_pages usp
                    WHERE usp.is_public = 1
                    AND usp.user_id != ?
                    AND usp.shared_roles LIKE ?
                    AND usp.id NOT IN (SELECT page_id FROM notifications_dismissed WHERE user_id = ?)
                    AND usp.id NOT IN (SELECT source_page_id FROM user_saved_pages WHERE user_id = ? AND source_page_id IS NOT NULL)";

            if ($stmt = $mysqli->prepare($sql)) {
                $userRolePattern = '%"' . $currentUserRole . '"%'; // Store in a variable
                $stmt->bind_param("isis", $currentUserId, $userRolePattern, $currentUserId, $currentUserId);
                if (!$stmt->execute()) {
                    error_log("Error executing get_notifications: " . $stmt->error);
                    sendJsonResponse('error', 'Failed to fetch notifications: ' . $stmt->error);
                }
                $result = $stmt->get_result();
                $notifications = [];
                while ($row = $result->fetch_assoc()) {
                    $notifications[] = $row;
                }
                sendJsonResponse('success', 'Notifications fetched.', ['data' => $notifications]);
                $stmt->close();
            } else {
                error_log("Failed to prepare get_notifications statement: " . $mysqli->error);
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;

        case 'dismiss_notification':
            if (!isset($_POST['page_id'])) {
                sendJsonResponse('error', 'Page ID is required to dismiss notification.');
            }
            $pageId = $_POST['page_id'];
            // Insert into notifications_dismissed table
            $sql = "INSERT INTO notifications_dismissed (user_id, page_id, dismissed_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE dismissed_at = NOW()";
            if ($stmt = $mysqli->prepare($sql)) {
                $stmt->bind_param("ii", $currentUserId, $pageId);
                if ($stmt->execute()) {
                    sendJsonResponse('success', 'Notification dismissed.');
                } else {
                    sendJsonResponse('error', 'Failed to dismiss notification: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement: ' . $mysqli->error);
            }
            break;
        case 'keep_shared_page':
            if (!isset($_POST['source_page_id'], $_POST['source_creator_username'], $_POST['page_name'], $_POST['page_url'])) {
                sendJsonResponse('error', 'Missing required fields for keeping shared page.');
            }

            $sourcePageId = $_POST['source_page_id'];
            $sourceCreatorUsername = $_POST['source_creator_username'];
            $pageName = $_POST['page_name'];
            $pageUrl = $_POST['page_url'];

            // Check if the user already has a copy of this page (by source_page_id if available, or by name/url)
            $checkSql = "SELECT id FROM user_saved_pages WHERE user_id = ? AND (source_page_id = ? OR (name = ? AND url = ?))";
            if ($checkStmt = $mysqli->prepare($checkSql)) {
                $checkStmt->bind_param("iiss", $currentUserId, $sourcePageId, $pageName, $pageUrl);
                $checkStmt->execute();
                $checkResult = $checkStmt->get_result();
                if ($checkResult->num_rows > 0) {
                    sendJsonResponse('error', 'You already have a copy of this page.');
                }
                $checkStmt->close();
            }

            // Create a new user saved page entry for the current user
            $sql = "INSERT INTO user_saved_pages (user_id, name, url, is_public, shared_roles, creation_time, source_page_id, source_creator_username, creator_username) VALUES (?, ?, ?, 0, '[]', NOW(), ?, ?, ?)";
            if ($stmt = $mysqli->prepare($sql)) {
                // isPublic and sharedRoles are set to default values for kept pages
                $stmt->bind_param("issiis", $currentUserId, $pageName, $pageUrl, $sourcePageId, $sourceCreatorUsername, $currentUsername);

                if ($stmt->execute()) {
                    // Optionally, dismiss the notification after keeping the page
                    $dismissSql = "INSERT INTO notifications_dismissed (user_id, page_id, dismissed_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE dismissed_at = NOW()";
                    if ($dismissStmt = $mysqli->prepare($dismissSql)) {
                        $dismissStmt->bind_param("ii", $currentUserId, $sourcePageId);
                        $dismissStmt->execute();
                        $dismissStmt->close();
                    }
                    sendJsonResponse('success', 'Page added to your saved pages!');
                } else {
                    sendJsonResponse('error', 'Failed to add page to your saved pages: ' . $stmt->error);
                }
                $stmt->close();
            } else {
                sendJsonResponse('error', 'Failed to prepare statement for keeping shared page: ' . $mysqli->error);
            }
            break;

        default:
            sendJsonResponse('error', 'Invalid API action.');
            break;
    }
    $mysqli->close(); // Close DB connection after API response
    exit(); // Exit after sending JSON response
}

// --- 4. HTML Structure for Dashboard ---
// This block is only reached if no 'action' parameter is present (i.e., a regular page load).
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OshoNet Admin Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        body.dark-mode {
            background-color: #1a202c; /* Tailwind gray-900 */
            color: #e2e8f0; /* Tailwind gray-200 */
        }
        body.dark-mode .bg-white {
            background-color: #2d3748; /* Tailwind gray-800 */
            color: #e2e8f0;
        }
        body.dark-mode .text-gray-800 {
            color: #e2e8f0;
        }
        body.dark-mode .text-gray-600 {
            color: #cbd5e0; /* Tailwind gray-300 */
        }
        body.dark-mode .text-gray-500 {
            color: #a0aec0; /* Tailwind gray-400 */
        }
        body.dark-mode .border-gray-300 {
            border-color: #4a5568; /* Tailwind gray-600 */
        }
        body.dark-mode input,
        body.dark-mode .modal-content {
            background-color: #4a5568; /* Tailwind gray-600 */
            color: #e2e8f0;
            border-color: #6b7280; /* Tailwind gray-500 */
        }
        body.dark-mode input::placeholder {
            color: #a0aec0;
        }
        body.dark-mode .filter-dropdown,
        body.dark-mode .notification-dropdown {
            background-color: #2d3748;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.5);
        }
        body.dark-mode .filter-dropdown a,
        body.dark-mode .notification-item {
            color: #e2e8f0;
        }
        body.dark-mode .filter-dropdown a:hover,
        body.dark-mode .notification-item:hover {
            background-color: #4a5568;
        }
        body.dark-mode .bg-gray-200 {
            background-color: #4a5568;
            color: #e2e8f0;
        }
        body.dark-mode .bg-gray-200:hover {
            background-color: #6b7280;
        }
        body.dark-mode .bg-gray-300 {
            background-color: #6b7280;
            color: #e2e8f0;
        }
        body.dark-mode .bg-gray-300:hover {
            background-color: #4a5568;
        }
        body.dark-mode .modal-close {
            color: #a0aec0;
        }
        body.dark-mode .modal-close:hover {
            color: #e2e8f0;
        }
        body.dark-mode .website-card {
            background-color: #2d3748;
            border-color: #4a5568;
        }
        body.dark-mode .website-card.bg-blue-50 {
            background-color: #2c5282; /* Darker blue for my pages */
            border-color: #4299e1;
        }
        body.dark-mode .website-card.bg-green-50 {
            background-color: #2f855a; /* Darker green for shared pages */
            border-color: #48bb78;
        }
        body.dark-mode .website-card.bg-red-50 {
            background-color: #9b2c2c; /* Darker red for dev sites */
            border-color: #e53e3e;
        }
        body.dark-mode .website-card .text-blue-600 {
            color: #63b3ed;
        }
        body.dark-mode .website-card .text-gray-400 {
            color: #cbd5e0;
        }

        /* Custom styles for the filter dropdown */
        .filter-dropdown {
            display: none;
            position: absolute;
            background-color: #fff;
            min-width: 160px;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
            z-index: 10; /* Increased z-index for dropdowns */
            border-radius: 0.5rem;
            overflow: hidden;
            right: 0; /* Align to the right of its parent */
            top: 100%; /* Position below the filter button */
            margin-top: 0.5rem; /* Space below the button */
        }
        .filter-dropdown a {
            color: black;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
            font-weight: 500;
        }
        .filter-dropdown a:hover {
            background-color: #f3f4f6; /* Tailwind gray-100 */
        }
        .filter-dropdown.show {
            display: block;
        }

        /* Modal specific styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 100; /* High z-index to be on top */
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
            align-items: center;
            justify-content: center;
        }
        .modal-content {
            background-color: #fefefe;
            margin: auto;
            padding: 2rem;
            border-radius: 0.75rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            width: 90%;
            max-width: 500px;
            animation: fadeIn 0.3s ease-out;
        }
        .modal-close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
        }
        .modal-close:hover,
        .modal-close:focus {
            color: black;
            text-decoration: none;
            cursor: pointer;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .modal.show {
            display: flex;
        }

        /* Notification styles */
        .notification-dropdown {
            display: none;
            position: absolute;
            background-color: #fff;
            min-width: 280px;
            max-height: 400px;
            overflow-y: auto;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
            z-index: 20; /* Higher than other dropdowns */
            border-radius: 0.5rem;
            right: 0;
            top: 100%;
            margin-top: 0.5rem;
        }
        .notification-dropdown.show {
            display: block;
        }
        .notification-item {
            padding: 12px 16px;
            border-bottom: 1px solid #f3f4f6;
        }
        .notification-item:last-child {
            border-bottom: none;
        }
        .notification-item button {
            margin-left: 0.5rem;
        }
        .notification-badge {
            position: absolute;
            top: -5px;
            right: -5px;
            background-color: red;
            color: white;
            border-radius: 50%;
            padding: 2px 6px;
            font-size: 0.75rem;
            font-weight: bold;
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen flex flex-col">
    <header class="bg-white shadow-md py-4 px-6 flex justify-between items-center sticky top-0 z-10 dark:bg-gray-800">
        <h1 class="text-3xl font-extrabold text-gray-800 dark:text-white">OshoNet Admin</h1>
        <div class="flex items-center space-x-4">
            <div class="relative">
                <button id="settings-button" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-2 px-3 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                    <i class="fas fa-cog text-xl"></i>
                </button>
                <div id="settings-dropdown" class="filter-dropdown dark:bg-gray-800">
                    <div class="p-4 font-semibold text-gray-800 border-b dark:text-white dark:border-gray-700">Settings</div>
                    <div class="py-2">
                        <a href="#" id="toggle-dark-mode" class="flex items-center space-x-2 dark:text-gray-200 dark:hover:bg-gray-700">
                            <i class="fas fa-moon"></i>
                            <span>Toggle Dark Mode</span>
                        </a>
                        <a href="#" id="delete-all-pages-button" class="flex items-center space-x-2 text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300">
                            <i class="fas fa-trash-alt"></i>
                            <span>Delete All My Pages</span>
                        </a>
                        <div class="px-4 py-2 text-gray-600 text-sm font-semibold dark:text-gray-400">Responsive View (Tailwind CSS)</div>
                        <div class="px-4 py-1 text-gray-500 text-xs dark:text-gray-500">
                            This dashboard is designed to be fully responsive using Tailwind CSS.
                            It adapts automatically to different screen sizes (mobile, tablet, desktop).
                            You can test this by resizing your browser window.
                        </div>
                    </div>
                </div>
            </div>

            <div class="relative">
                <button id="notification-button" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-2 px-3 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                    <i class="fas fa-bell text-xl"></i>
                    <span id="notification-count" class="notification-badge hidden">0</span>
                </button>
                <div id="notification-dropdown" class="notification-dropdown dark:bg-gray-800">
                    <div class="p-4 font-semibold text-gray-800 border-b dark:text-white dark:border-gray-700">Notifications</div>
                    <div id="notification-list" class="py-2">
                        <div class="text-center text-gray-500 p-4" id="no-notifications-message">No new notifications.</div>
                    </div>
                </div>
            </div>

            <span class="text-gray-600 text-lg font-medium dark:text-gray-300">Welcome, <span class="text-blue-600 font-semibold dark:text-blue-400"><?php echo htmlspecialchars($currentUsername); ?></span> (<span class="capitalize"><?php echo htmlspecialchars(str_replace('_', ' ', $currentUserRole)); ?></span>)</span>
            <a href="login.php?action=logout" class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg shadow transition duration-300 ease-in-out transform hover:-translate-y-0.5">
                <i class="fas fa-sign-out-alt mr-2"></i>Logout
            </a>
        </div>
    </header>

    <main class="flex-grow container mx-auto p-6">
        <div class="bg-white rounded-xl shadow-lg p-8 mb-8 dark:bg-gray-800">
            <div class="flex flex-col md:flex-row justify-between items-center mb-8 space-y-4 md:space-y-0 md:space-x-4">
                <h2 class="text-2xl font-bold text-gray-800 dark:text-white">All Websites</h2>
                <div class="relative w-full md:w-1/2">
                    <input type="text" id="search-input" placeholder="Search websites by name..."
                           class="w-full py-3 pl-12 pr-4 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ease-in-out text-lg shadow-sm dark:bg-gray-700 dark:text-white dark:border-gray-600 dark:placeholder-gray-400">
                    <i class="fas fa-search absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 text-xl dark:text-gray-500"></i>
                </div>

                <div class="flex space-x-3 relative">
                    <div class="relative">
                        <button id="type-filter-button" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-3 px-5 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center space-x-2 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                            <i class="fas fa-layer-group text-xl"></i>
                            <span class="hidden md:inline">Type</span>
                        </button>
                        <div id="type-filter-dropdown" class="filter-dropdown dark:bg-gray-800">
                            <a href="#" class="type-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-type-filter="all">All Types</a>
                            <a href="#" class="type-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-type-filter="official">Official Websites</a>
                            <a href="#" class="type-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-type-filter="my_pages">My Saved Pages</a>
                            <a href="#" class="type-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-type-filter="shared_pages">Shared Pages</a>
                        </div>
                    </div>

                    <div class="relative">
                        <button id="level-filter-button" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-3 px-5 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center space-x-2 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                            <i class="fas fa-filter text-xl"></i>
                            <span class="hidden md:inline">Level</span>
                        </button>
                        <div id="level-filter-dropdown" class="filter-dropdown dark:bg-gray-800">
                            <a href="#" class="level-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-level-filter="all">All Power Levels</a>
                            <a href="#" class="level-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-level-filter="owner">Owner</a>
                            <a href="#" class="level-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-level-filter="dev">Dev</a>
                            <a href="#" class="level-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-level-filter="upper_staff">Upper Staff</a>
                            <a href="#" class="level-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-level-filter="low_staff">Low Staff</a>
                            <a href="#" class="level-filter-option dark:text-gray-200 dark:hover:bg-gray-700" data-level-filter="reception">Reception</a>
                        </div>
                    </div>

                    <button id="sort-name-asc" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-3 px-5 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center space-x-2 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                        <i class="fas fa-sort-alpha-down text-xl"></i>
                        <span class="hidden md:inline">Name A-Z</span>
                    </button>
                    <button id="sort-name-desc" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-3 px-5 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center space-x-2 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                        <i class="fas fa-sort-alpha-up text-xl"></i>
                        <span class="hidden md:inline">Name Z-A</span>
                    </button>
                    <button id="sort-popularity" class="bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-3 px-5 rounded-lg shadow-sm transition duration-300 ease-in-out flex items-center space-x-2 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">
                        <i class="fas fa-fire text-xl"></i>
                        <span class="hidden md:inline">Popular</span>
                    </button>
                </div>
            </div>

            <div id="websites-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div class="col-span-full text-center text-gray-500 text-xl py-10" id="loading-message">Loading websites...</div>
                <div class="col-span-full text-center text-gray-500 text-xl py-10 hidden" id="no-results-message">No websites found.</div>
            </div>
            <div class="flex justify-center mt-8">
                <button id="add-page-button" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-full shadow-lg transition duration-300 ease-in-out transform hover:-translate-y-0.5">
                    <i class="fas fa-plus mr-2"></i>Add New Saved Page
                </button>
            </div>
        </div>
    </main>

    <div id="page-modal" class="modal">
        <div class="modal-content dark:bg-gray-700">
            <span class="modal-close dark:text-gray-400 hover:dark:text-white">&times;</span>
            <h3 class="text-2xl font-bold text-gray-800 mb-6 dark:text-white" id="modal-title">Add New Saved Page</h3>
            <form id="page-form" class="space-y-5">
                <input type="hidden" id="page-id" name="id">
                <div>
                    <label for="page-name" class="block text-gray-700 text-sm font-semibold mb-2 dark:text-gray-300">Page Name:</label>
                    <input type="text" id="page-name-input" name="name" required class="w-full py-2 px-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-600 dark:text-white dark:border-gray-500">
                </div>
                <div>
                    <label for="page-url" class="block text-gray-700 text-sm font-semibold mb-2 dark:text-gray-300">URL:</label>
                    <input type="url" id="page-url-input" name="url" required class="w-full py-2 px-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-600 dark:text-white dark:border-gray-500">
                </div>
                <div class="flex items-center space-x-3">
                    <input type="checkbox" id="is-public" name="is_public" class="form-checkbox h-5 w-5 text-blue-600 rounded-md dark:bg-gray-600 dark:border-gray-500">
                    <label for="is-public" class="text-gray-700 font-semibold dark:text-gray-300">Make Public</label>
                </div>
                <div id="shared-roles-container" class="hidden">
                    <label class="block text-gray-700 text-sm font-semibold mb-2 dark:text-gray-300">Share with Roles:</label>
                    <div class="grid grid-cols-2 gap-2">
                        <?php foreach ($allRoles as $role): ?>
                            <div class="flex items-center">
                                <input type="checkbox" id="role-<?php echo $role; ?>" name="shared_roles[]" value="<?php echo $role; ?>" class="form-checkbox h-4 w-4 text-blue-600 rounded-sm dark:bg-gray-600 dark:border-gray-500">
                                <label for="role-<?php echo $role; ?>" class="ml-2 text-gray-700 capitalize dark:text-gray-300"><?php echo str_replace('_', ' ', $role); ?></label>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <div>
                    <label for="deletion-time" class="block text-gray-700 text-sm font-semibold mb-2 dark:text-gray-300">Delete On (Optional):</label>
                    <input type="datetime-local" id="deletion-time" name="deletion_time" class="w-full py-2 px-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-600 dark:text-white dark:border-gray-500">
                </div>
                <div class="flex justify-end space-x-3">
                    <button type="button" id="cancel-page-button" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg shadow-sm transition duration-300 dark:bg-gray-600 dark:text-gray-200 dark:hover:bg-gray-500">
                        Cancel
                    </button>
                    <button type="submit" id="save-page-button" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg shadow transition duration-300">
                        Save Page
                    </button>
                </div>
                <div id="modal-message" class="mt-4 text-center text-sm hidden"></div>
            </form>
        </div>
    </div>

    <div id="confirm-modal" class="modal">
        <div class="modal-content max-w-sm dark:bg-gray-700">
            <h3 class="text-xl font-bold text-gray-800 mb-4 dark:text-white">Confirm Deletion</h3>
            <p id="confirm-message" class="text-gray-700 mb-6 dark:text-gray-300">Are you sure you want to delete this page?</p>
            <div class="flex justify-end space-x-3">
                <button type="button" id="cancel-confirm-button" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg shadow-sm transition duration-300 dark:bg-gray-600 dark:text-gray-200 dark:hover:bg-gray-500">
                    Cancel
                </button>
                <button type="button" id="execute-delete-button" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg shadow transition duration-300">
                    Delete
                </button>
            </div>
        </div>
    </div>

    <div id="deleteAllStep1Modal" class="modal">
        <div class="modal-content max-w-md dark:bg-gray-700">
            <span class="modal-close dark:text-gray-400 hover:dark:text-white">&times;</span>
            <h3 class="text-xl font-bold text-gray-800 mb-4 dark:text-white">Confirm Deletion of All My Pages</h3>
            <p class="text-gray-700 mb-6 dark:text-gray-300">
                This action will permanently delete ALL pages you have personally saved.
                This cannot be undone. Are you absolutely sure?
            </p>
            <div class="flex justify-end space-x-3">
                <button type="button" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg shadow-sm transition duration-300 modal-close-btn dark:bg-gray-600 dark:text-gray-200 dark:hover:bg-gray-500">
                    Cancel
                </button>
                <button type="button" id="confirm-delete-all-step1" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg shadow transition duration-300">
                    Yes, Delete All My Pages
                </button>
            </div>
        </div>
    </div>

    <div id="deleteAllStep2Modal" class="modal">
        <div class="modal-content max-w-md dark:bg-gray-700">
            <span class="modal-close dark:text-gray-400 hover:dark:text-white">&times;</span>
            <h3 class="text-xl font-bold text-gray-800 mb-4 dark:text-white">Final Confirmation</h3>
            <p class="text-gray-700 mb-4 dark:text-gray-300">
                To confirm, please type "<span class="font-bold text-red-600">DELETE ALL</span>" in the box below:
            </p>
            <input type="text" id="deleteAllConfirmationInput" class="w-full py-2 px-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent mb-6 dark:bg-gray-600 dark:text-white dark:border-gray-500">
            <div id="deleteAllMessage" class="mt-4 text-center text-sm hidden"></div>
            <div class="flex justify-end space-x-3">
                <button type="button" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg shadow-sm transition duration-300 modal-close-btn dark:bg-gray-600 dark:text-gray-200 dark:hover:bg-gray-500">
                    Cancel
                </button>
                <button type="button" id="confirm-delete-all-step2" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg shadow transition duration-300">
                    Confirm Deletion
                </button>
            </div>
        </div>
    </div>


    <div id="deleteAllStep3Modal" class="modal">
        <div class="modal-content max-w-sm text-center dark:bg-gray-700">
            <span class="modal-close dark:text-gray-400 hover:dark:text-white">&times;</span>
            <div id="deleteAllFinalMessage" class="text-lg font-semibold mt-4"></div>
            <button type="button" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg mt-6 modal-close-btn">Close</button>
        </div>
    </div>


    <script>
        const websitesList = document.getElementById('websites-list');
        const searchInput = document.getElementById('search-input');
        const addPageButton = document.getElementById('add-page-button');
        const pageModal = document.getElementById('page-modal');
        const modalClose = pageModal.querySelector('.modal-close');
        const pageForm = document.getElementById('page-form');
        const modalTitle = document.getElementById('modal-title');
        const pageIdInput = document.getElementById('page-id');
        const pageNameInput = document.getElementById('page-name-input');
        const pageUrlInput = document.getElementById('page-url-input');
        const isPublicCheckbox = document.getElementById('is-public');
        const sharedRolesContainer = document.getElementById('shared-roles-container');
        const modalMessage = document.getElementById('modal-message');
        const confirmModal = document.getElementById('confirm-modal');
        const confirmMessage = document.getElementById('confirm-message');
        const cancelConfirmButton = document.getElementById('cancel-confirm-button');
        const executeDeleteButton = document.getElementById('execute-delete-button');
        const cancelButton = document.getElementById('cancel-page-button');
        const loadingMessage = document.getElementById('loading-message');
        const noResultsMessage = document.getElementById('no-results-message');

        const typeFilterButton = document.getElementById('type-filter-button');
        const typeFilterDropdown = document.getElementById('type-filter-dropdown');
        const typeFilterOptions = document.querySelectorAll('.type-filter-option');

        const levelFilterButton = document.getElementById('level-filter-button');
        const levelFilterDropdown = document.getElementById('level-filter-dropdown');
        const levelFilterOptions = document.querySelectorAll('.level-filter-option');

        const sortNameAscButton = document.getElementById('sort-name-asc');
        const sortNameDescButton = document.getElementById('sort-name-desc');
        const sortPopularityButton = document.getElementById('sort-popularity');

        const notificationButton = document.getElementById('notification-button');
        const notificationDropdown = document.getElementById('notification-dropdown');
        const notificationList = document.getElementById('notification-list');
        const notificationCountBadge = document.getElementById('notification-count');
        const noNotificationsMessage = document.getElementById('no-notifications-message');

        const settingsButton = document.getElementById('settings-button');
        const settingsDropdown = document.getElementById('settings-dropdown');
        const toggleDarkModeButton = document.getElementById('toggle-dark-mode');
        const deleteAllPagesButton = document.getElementById('delete-all-pages-button');

        const deleteAllStep1Modal = document.getElementById('deleteAllStep1Modal');
        const confirmDeleteAllStep1 = document.getElementById('confirm-delete-all-step1');
        const deleteAllStep2Modal = document.getElementById('deleteAllStep2Modal');
        const deleteAllConfirmationInput = document.getElementById('deleteAllConfirmationInput');
        const confirmDeleteAllStep2 = document.getElementById('confirm-delete-all-step2');
        const deleteAllMessage = document.getElementById('deleteAllMessage');
        const deleteAllStep3Modal = document.getElementById('deleteAllStep3Modal');
        const deleteAllFinalMessage = document.getElementById('deleteAllFinalMessage');

        let currentTypeFilter = 'all';
        let currentLevelFilter = 'all';
        let currentSort = 'name_asc'; // Default sort

        // Function to toggle modal visibility
        function openModal(modal) {
            modal.classList.add('show');
        }

        function closeModal(modal) {
            modal.classList.remove('show');
            // Clear form and messages when modal closes
            if (modal === pageModal) {
                pageForm.reset();
                modalMessage.textContent = '';
                modalMessage.classList.add('hidden');
                sharedRolesContainer.classList.add('hidden'); // Hide shared roles by default
                pageIdInput.value = ''; // Clear hidden ID
            }
            if (modal === confirmModal) {
                executeDeleteButton.dataset.pageId = ''; // Clear ID from dataset
            }
            if (modal === deleteAllStep2Modal) {
                deleteAllConfirmationInput.value = '';
                deleteAllMessage.textContent = '';
                deleteAllMessage.classList.add('hidden');
            }
            if (modal === deleteAllStep3Modal) {
                deleteAllFinalMessage.textContent = '';
            }
        }

        // Close dropdowns when clicking outside
        window.addEventListener('click', function(event) {
            if (!typeFilterButton.contains(event.target) && !typeFilterDropdown.contains(event.target)) {
                typeFilterDropdown.classList.remove('show');
            }
            if (!levelFilterButton.contains(event.target) && !levelFilterDropdown.contains(event.target)) {
                levelFilterDropdown.classList.remove('show');
            }
            if (!notificationButton.contains(event.target) && !notificationDropdown.contains(event.target)) {
                notificationDropdown.classList.remove('show');
            }
            if (!settingsButton.contains(event.target) && !settingsDropdown.contains(event.target)) {
                settingsDropdown.classList.remove('show');
            }
        });


        // Handle modal closing via 'x' button or cancel button
        document.querySelectorAll('.modal .modal-close, .modal .modal-close-btn').forEach(button => {
            button.addEventListener('click', function() {
                closeModal(this.closest('.modal'));
            });
        });

        // Toggle dropdowns
        typeFilterButton.addEventListener('click', function(event) {
            event.stopPropagation(); // Prevent click from bubbling to window and closing
            typeFilterDropdown.classList.toggle('show');
            levelFilterDropdown.classList.remove('show'); // Close other dropdowns
            settingsDropdown.classList.remove('show');
            notificationDropdown.classList.remove('show');
        });

        levelFilterButton.addEventListener('click', function(event) {
            event.stopPropagation(); // Prevent click from bubbling to window and closing
            levelFilterDropdown.classList.toggle('show');
            typeFilterDropdown.classList.remove('show'); // Close other dropdowns
            settingsDropdown.classList.remove('show');
            notificationDropdown.classList.remove('show');
        });

        notificationButton.addEventListener('click', function(event) {
            event.stopPropagation();
            notificationDropdown.classList.toggle('show');
            typeFilterDropdown.classList.remove('show');
            levelFilterDropdown.classList.remove('show');
            settingsDropdown.classList.remove('show');
        });

        settingsButton.addEventListener('click', function(event) {
            event.stopPropagation();
            settingsDropdown.classList.toggle('show');
            typeFilterDropdown.classList.remove('show');
            levelFilterDropdown.classList.remove('show');
            notificationDropdown.classList.remove('show');
        });

        // Initial fetch of websites
        async function fetchAllWebsites(search = '', type = 'all', level = 'all', sort = 'name_asc') {
            loadingMessage.classList.remove('hidden');
            noResultsMessage.classList.add('hidden');
            websitesList.innerHTML = ''; // Clear current list

            currentTypeFilter = type;
            currentLevelFilter = level;
            currentSort = sort;

            try {
                const response = await fetch(`index.php?action=get_all_websites&search=${encodeURIComponent(search)}&type_filter=${type}&level_filter=${level}&sort=${sort}`);
                const result = await response.json();

                if (result.status === 'success') {
                    const websites = result.data;
                    if (websites.length > 0) {
                        websites.forEach(website => {
                            const card = document.createElement('div');
                            let bgColorClass = 'bg-white';
                            let typeLabel = '';
                            let isEditable = false;
                            let isDeletable = false;
                            let creatorInfo = '';
                            let deletionTimeInfo = '';

                            if (website.type === 'official') {
                                typeLabel = 'Official Website';
                                // Apply specific color for 'dev' power_level
                                if (website.power_level === 'dev') {
                                    bgColorClass = 'bg-red-50 dark:bg-red-900';
                                } else {
                                    bgColorClass = 'bg-white dark:bg-gray-800';
                                }
                                creatorInfo = `<p class="text-sm text-gray-500 dark:text-gray-400">Created by: ${htmlspecialchars(website.creator_username)}</p>`;
                            } else if (website.type === 'my_page') {
                                bgColorClass = 'bg-blue-50 dark:bg-blue-900';
                                typeLabel = 'My Saved Page';
                                isEditable = true;
                                isDeletable = true;
                                creatorInfo = `<p class="text-sm text-gray-500 dark:text-gray-400">Created by: ${htmlspecialchars(website.creator_username)}</p>`;
                                if (website.deletion_time) {
                                    deletionTimeInfo = `<p class="text-sm text-red-600 dark:text-red-400">Deletes on: ${formatDateTime(website.deletion_time)}</p>`;
                                }
                            } else if (website.type === 'shared_page') {
                                bgColorClass = 'bg-green-50 dark:bg-green-900';
                                typeLabel = 'Shared Page';
                                // Shared pages are not directly editable/deletable by the recipient
                                creatorInfo = `<p class="text-sm text-gray-500 dark:text-gray-400">Shared by: ${htmlspecialchars(website.creator_username)}</p>`;
                                if (website.deletion_time) {
                                    deletionTimeInfo = `<p class="text-sm text-red-600 dark:text-red-400">Deletes on: ${formatDateTime(website.deletion_time)}</p>`;
                                }
                            }

                            // Popularity for official websites
                            let popularitySection = '';
                            if (website.type === 'official' && website.popularity_score !== undefined) {
                                popularitySection = `
                                    <div class="flex items-center text-gray-600 dark:text-gray-300">
                                        <i class="fas fa-fire text-orange-500 mr-2"></i>
                                        <span>Popularity: ${website.popularity_score}</span>
                                    </div>
                                `;
                            }

                            let powerLevelInfo = '';
                            if (website.power_level) {
                                powerLevelInfo = `<p class="text-sm text-gray-500 dark:text-gray-400">Level: <span class="capitalize">${htmlspecialchars(website.power_level.replace('_', ' '))}</span></p>`;
                            }


                            card.className = `website-card ${bgColorClass} rounded-lg shadow-md p-6 flex flex-col justify-between transition duration-300 ease-in-out transform hover:-translate-y-1 hover:shadow-xl`;
                            card.innerHTML = `
                                <div>
                                    <h3 class="text-xl font-semibold text-gray-800 mb-2 dark:text-white">${htmlspecialchars(website.name)}</h3>
                                    <p class="text-blue-600 hover:underline mb-2 break-all dark:text-blue-400">
                                        <a href="${htmlspecialchars(website.url)}" target="_blank" rel="noopener noreferrer">${htmlspecialchars(website.url)}</a>
                                    </p>
                                    <div class="flex items-center text-gray-600 mb-2 dark:text-gray-300">
                                        <span class="text-sm font-medium px-2 py-1 rounded-full ${website.type === 'official' ? 'bg-gray-200 text-gray-700 dark:bg-gray-600 dark:text-gray-200' : (website.type === 'my_page' ? 'bg-blue-200 text-blue-700 dark:bg-blue-700 dark:text-blue-200' : 'bg-green-200 text-green-700 dark:bg-green-700 dark:text-green-200')}">
                                            ${typeLabel}
                                        </span>
                                    </div>
                                    ${creatorInfo}
                                    ${powerLevelInfo}
                                    ${deletionTimeInfo}
                                    ${popularitySection}
                                </div>
                                <div class="flex mt-4 space-x-2">
                                    ${website.type === 'official' ? `<button class="save-page-button bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg shadow-md transition duration-300" data-id="${website.id}" data-name="${htmlspecialchars(website.name)}" data-url="${htmlspecialchars(website.url)}" data-power-level="${htmlspecialchars(website.power_level)}" data-creator-username="${htmlspecialchars(website.creator_username)}">
                                        <i class="fas fa-save mr-2"></i>Save
                                    </button>` : ''}
                                    ${isEditable ? `<button class="edit-page-button bg-yellow-500 hover:bg-yellow-600 text-white py-2 px-4 rounded-lg shadow-md transition duration-300" data-id="${website.id}" data-name="${htmlspecialchars(website.name)}" data-url="${htmlspecialchars(website.url)}" data-is-public="${website.is_public}" data-shared-roles='${website.shared_roles}' data-deletion-time="${website.deletion_time || ''}">
                                        <i class="fas fa-edit mr-2"></i>Edit
                                    </button>` : ''}
                                    ${isDeletable ? `<button class="delete-page-button bg-red-500 hover:bg-red-600 text-white py-2 px-4 rounded-lg shadow-md transition duration-300" data-id="${website.id}">
                                        <i class="fas fa-trash-alt mr-2"></i>Delete
                                    </button>` : ''}
                                </div>
                            `;
                            websitesList.appendChild(card);
                        });
                        addEventListenersToWebsiteCards();
                    } else {
                        noResultsMessage.classList.remove('hidden');
                    }
                } else {
                    console.error('Error fetching websites:', result.message);
                    noResultsMessage.textContent = 'Error loading websites. Please try again.';
                    noResultsMessage.classList.remove('hidden');
                }
            } catch (error) {
                console.error('Network error fetching websites:', error);
                noResultsMessage.textContent = 'Network error. Please check your connection.';
                noResultsMessage.classList.remove('hidden');
            } finally {
                loadingMessage.classList.add('hidden');
            }
        }

        // Add event listeners to website cards (for save, edit, delete buttons)
        function addEventListenersToWebsiteCards() {
            // Save Official Page
            document.querySelectorAll('.save-page-button').forEach(button => {
                button.addEventListener('click', async function() {
                    const id = this.dataset.id;
                    const name = this.dataset.name;
                    const url = this.dataset.url;
                    const creatorUsername = this.dataset.creatorUsername; // This will be 'System' for official pages
                    const powerLevel = this.dataset.powerLevel; // Official site's power level (not directly used for saving to user_saved_pages but available)


                    const formData = new FormData();
                    formData.append('action', 'keep_shared_page');
                    formData.append('source_page_id', id);
                    formData.append('source_creator_username', creatorUsername); // Corrected: Pass creatorUsername
                    formData.append('page_name', name);
                    formData.append('page_url', url);
                    // For official pages being saved, they are saved as private by default,
                    // so is_public is 0 and shared_roles is '[]'.
                    // The backend handles this by setting is_public to 0 and shared_roles to '[]' automatically for 'keep_shared_page'.

                    try {
                        const response = await fetch('index.php', {
                            method: 'POST',
                            body: formData
                        });
                        const result = await response.json();
                        if (result.status === 'success') {
                            alert(result.message);
                            fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, currentSort); // Refresh list
                            fetchNotifications(); // Refresh notifications as saving dismisses them
                        } else {
                            alert('Error: ' + result.message);
                        }
                    } catch (error) {
                        console.error('Error saving page:', error);
                        alert('An unexpected error occurred while saving the page.');
                    }
                });
            });

            // Edit User Page
            document.querySelectorAll('.edit-page-button').forEach(button => {
                button.addEventListener('click', function() {
                    modalTitle.textContent = 'Edit Saved Page';
                    pageIdInput.value = this.dataset.id;
                    pageNameInput.value = htmlspecialchars_decode(this.dataset.name);
                    pageUrlInput.value = htmlspecialchars_decode(this.dataset.url);

                    const isPublic = this.dataset.isPublic === '1';
                    isPublicCheckbox.checked = isPublic;

                    const sharedRoles = JSON.parse(this.dataset.sharedRoles);
                    document.querySelectorAll('input[name="shared_roles[]"]').forEach(checkbox => {
                        checkbox.checked = sharedRoles.includes(checkbox.value);
                    });

                    // Show/hide shared roles container based on is_public
                    if (isPublic) {
                        sharedRolesContainer.classList.remove('hidden');
                    } else {
                        sharedRolesContainer.classList.add('hidden');
                    }

                    // Set deletion time
                    const deletionTime = this.dataset.deletionTime;
                    document.getElementById('deletion-time').value = deletionTime ? formatDateTimeForInput(deletionTime) : '';

                    openModal(pageModal);
                });
            });

            // Delete User Page
            document.querySelectorAll('.delete-page-button').forEach(button => {
                button.addEventListener('click', function() {
                    const pageId = this.dataset.id;
                    confirmMessage.textContent = 'Are you sure you want to delete this page?';
                    executeDeleteButton.dataset.pageId = pageId; // Store ID for deletion
                    openModal(confirmModal);
                });
            });
        }

        // Handle create/update page form submission
        pageForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            const formData = new FormData(pageForm);
            const pageId = pageIdInput.value;
            const action = pageId ? 'update_user_page' : 'create_user_page';
            formData.append('action', action);

            // Handle is_public and shared_roles
            formData.set('is_public', isPublicCheckbox.checked ? '1' : '0');
            if (!isPublicCheckbox.checked) {
                formData.set('shared_roles', '[]'); // Clear shared roles if not public
            } else {
                const selectedRoles = Array.from(document.querySelectorAll('input[name="shared_roles[]"]:checked'))
                                          .map(cb => cb.value);
                formData.set('shared_roles', JSON.stringify(selectedRoles));
            }

            try {
                const response = await fetch('index.php', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();

                modalMessage.textContent = result.message;
                modalMessage.classList.remove('hidden');

                if (result.status === 'success') {
                    modalMessage.classList.remove('text-red-600');
                    modalMessage.classList.add('text-green-600');
                    setTimeout(() => {
                        closeModal(pageModal);
                        fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, currentSort); // Refresh websites
                    }, 1500);
                } else {
                    modalMessage.classList.remove('text-green-600');
                    modalMessage.classList.add('text-red-600');
                }
            } catch (error) {
                console.error('Error saving page:', error);
                modalMessage.textContent = 'An unexpected error occurred.';
                modalMessage.classList.remove('text-green-600');
                modalMessage.classList.add('text-red-600');
            }
        });

        // Toggle shared roles visibility
        isPublicCheckbox.addEventListener('change', function() {
            if (this.checked) {
                sharedRolesContainer.classList.remove('hidden');
            } else {
                sharedRolesContainer.classList.add('hidden');
                // Uncheck all shared roles when 'Make Public' is unchecked
                document.querySelectorAll('input[name="shared_roles[]"]').forEach(checkbox => {
                    checkbox.checked = false;
                });
            }
        });

        // Handle delete confirmation
        executeDeleteButton.addEventListener('click', async function() {
            const pageIdToDelete = this.dataset.pageId;
            if (pageIdToDelete) {
                const formData = new FormData();
                formData.append('action', 'delete_user_page');
                formData.append('id', pageIdToDelete);

                try {
                    const response = await fetch('index.php', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    if (result.status === 'success') {
                        alert(result.message); // Use alert for simplicity in this example
                        closeModal(confirmModal);
                        fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, currentSort); // Refresh websites
                    } else {
                        alert('Error: ' + result.message);
                    }
                } catch (error) {
                    console.error('Error deleting page:', error);
                    alert('An unexpected error occurred during deletion.');
                }
            }
        });

        // Search input event listener
        let searchTimeout;
        searchInput.addEventListener('keyup', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, currentSort);
            }, 300); // Debounce search
        });

        // Type filter options event listeners
        typeFilterOptions.forEach(option => {
            option.addEventListener('click', function(event) {
                event.preventDefault();
                typeFilterDropdown.classList.remove('show');
                const filterType = this.dataset.typeFilter;
                fetchAllWebsites(searchInput.value, filterType, currentLevelFilter, currentSort);
            });
        });

        // Level filter options event listeners
        levelFilterOptions.forEach(option => {
            option.addEventListener('click', function(event) {
                event.preventDefault();
                levelFilterDropdown.classList.remove('show');
                const filterLevel = this.dataset.levelFilter;
                fetchAllWebsites(searchInput.value, currentTypeFilter, filterLevel, currentSort);
            });
        });

        // Sort buttons event listeners
        sortNameAscButton.addEventListener('click', function() {
            fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, 'name_asc');
        });

        sortNameDescButton.addEventListener('click', function() {
            fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, 'name_desc');
        });

        sortPopularityButton.addEventListener('click', function() {
            fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, 'popularity_desc');
        });

        // Add New Page Button
        addPageButton.addEventListener('click', function() {
            modalTitle.textContent = 'Add New Saved Page';
            pageForm.reset(); // Clear form
            pageIdInput.value = ''; // Ensure ID is clear for new entry
            sharedRolesContainer.classList.add('hidden'); // Hide shared roles by default
            isPublicCheckbox.checked = false; // Uncheck public by default
            openModal(pageModal);
        });

        // Helper function for HTML escaping (to prevent XSS)
        function htmlspecialchars(str) {
            const div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
        }

        // Helper function for HTML unescaping (for populating form fields)
        function htmlspecialchars_decode(str) {
            const parser = new DOMParser();
            const doc = parser.parseFromString(str, 'text/html');
            return doc.documentElement.textContent;
        }

        // Helper to format datetime for input[type="datetime-local"]
        function formatDateTimeForInput(dateTimeString) {
            if (!dateTimeString) return '';
            const date = new Date(dateTimeString);
            const year = date.getFullYear();
            const month = (date.getMonth() + 1).toString().padStart(2, '0');
            const day = date.getDate().toString().padStart(2, '0');
            const hours = date.getHours().toString().padStart(2, '0');
            const minutes = date.getMinutes().toString().padStart(2, '0');
            return `${year}-${month}-${day}T${hours}:${minutes}`;
        }

        // Helper to format datetime for display
        function formatDateTime(dateTimeString) {
            if (!dateTimeString) return '';
            const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
            return new Date(dateTimeString).toLocaleString(undefined, options);
        }

        // --- Notifications Logic ---
        async function fetchNotifications() {
            try {
                const response = await fetch('index.php?action=get_notifications');
                const result = await response.json();

                if (result.status === 'success') {
                    const notifications = result.data;
                    notificationList.innerHTML = ''; // Clear current notifications

                    if (notifications.length > 0) {
                        notificationCountBadge.textContent = notifications.length;
                        notificationCountBadge.classList.remove('hidden');
                        noNotificationsMessage.classList.add('hidden');

                        notifications.forEach(notif => {
                            const notifItem = document.createElement('div');
                            notifItem.className = 'notification-item flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700';
                            notifItem.innerHTML = `
                                <div class="flex-grow">
                                    <p class="text-sm font-semibold text-gray-800 dark:text-white">${htmlspecialchars(notif.creator_username)} shared a page:</p>
                                    <p class="text-sm text-blue-600 hover:underline dark:text-blue-400">
                                        <a href="${htmlspecialchars(notif.url)}" target="_blank" rel="noopener noreferrer">${htmlspecialchars(notif.name)}</a>
                                    </p>
                                    <p class="text-xs text-gray-500 dark:text-gray-400">${formatDateTime(notif.creation_time)}</p>
                                </div>
                                <div class="flex flex-col space-y-1">
                                    <button class="keep-notification-button bg-blue-500 hover:bg-blue-600 text-white text-xs py-1 px-2 rounded-md transition duration-300"
                                            data-page-id="${notif.id}"
                                            data-source-creator-username="${htmlspecialchars(notif.source_creator_username || notif.creator_username)}"
                                            data-page-name="${htmlspecialchars(notif.name)}"
                                            data-page-url="${htmlspecialchars(notif.url)}">
                                        Keep
                                    </button>
                                    <button class="dismiss-notification-button bg-gray-400 hover:bg-gray-500 text-white text-xs py-1 px-2 rounded-md transition duration-300"
                                            data-page-id="${notif.id}">
                                        Dismiss
                                    </button>
                                </div>
                            `;
                            notificationList.appendChild(notifItem);
                        });
                        addEventListenersToNotifications();
                    } else {
                        notificationCountBadge.classList.add('hidden');
                        noNotificationsMessage.classList.remove('hidden');
                    }
                } else {
                    console.error('Error fetching notifications:', result.message);
                    notificationList.innerHTML = `<div class="text-center text-red-500 p-4">Error loading notifications.</div>`;
                    notificationCountBadge.classList.add('hidden');
                }
            } catch (error) {
                console.error('Network error fetching notifications:', error);
                notificationList.innerHTML = `<div class="text-center text-red-500 p-4">Network error.</div>`;
                notificationCountBadge.classList.add('hidden');
            }
        }

        function addEventListenersToNotifications() {
            // Dismiss Notification
            document.querySelectorAll('.dismiss-notification-button').forEach(button => {
                button.addEventListener('click', async function() {
                    const pageId = this.dataset.pageId;
                    const formData = new FormData();
                    formData.append('action', 'dismiss_notification');
                    formData.append('page_id', pageId);

                    try {
                        const response = await fetch('index.php', {
                            method: 'POST',
                            body: formData
                        });
                        const result = await response.json();
                        if (result.status === 'success') {
                            fetchNotifications(); // Refresh notifications
                        } else {
                            alert('Error dismissing notification: ' + result.message);
                        }
                    } catch (error) {
                        console.error('Error dismissing notification:', error);
                        alert('An unexpected error occurred.');
                    }
                });
            });

            // Keep Notification (Save shared page to my pages)
            document.querySelectorAll('.keep-notification-button').forEach(button => {
                button.addEventListener('click', async function() {
                    const sourcePageId = this.dataset.pageId;
                    const sourceCreatorUsername = this.dataset.sourceCreatorUsername;
                    const pageName = this.dataset.pageName;
                    const pageUrl = this.dataset.pageUrl;

                    const formData = new FormData();
                    formData.append('action', 'keep_shared_page');
                    formData.append('source_page_id', sourcePageId);
                    formData.append('source_creator_username', sourceCreatorUsername);
                    formData.append('page_name', pageName);
                    formData.append('page_url', pageUrl);

                    try {
                        const response = await fetch('index.php', {
                            method: 'POST',
                            body: formData
                        });
                        const result = await response.json();
                        if (result.status === 'success') {
                            alert(result.message);
                            fetchNotifications(); // Refresh notifications after keeping
                            fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, currentSort); // Refresh main list to show new page
                        } else {
                            alert('Error keeping page: ' + result.message);
                        }
                    } catch (error) {
                        console.error('Error keeping page:', error);
                        alert('An unexpected error occurred while keeping the page.');
                    }
                });
            });
        }


        // Dark Mode Toggle
        toggleDarkModeButton.addEventListener('click', (e) => {
            e.preventDefault();
            document.body.classList.toggle('dark-mode');
            // Save preference to localStorage
            if (document.body.classList.contains('dark-mode')) {
                localStorage.setItem('theme', 'dark');
            } else {
                localStorage.setItem('theme', 'light');
            }
        });

        // Apply saved theme preference on load
        document.addEventListener('DOMContentLoaded', () => {
            if (localStorage.getItem('theme') === 'dark') {
                document.body.classList.add('dark-mode');
            } else {
                document.body.classList.remove('dark-mode');
            }
            fetchAllWebsites();
            fetchNotifications();
            // Poll for new notifications every 30 seconds
            setInterval(fetchNotifications, 30000);
        });

        // --- Delete All My Pages Workflow ---
        deleteAllPagesButton.addEventListener('click', (e) => {
            e.preventDefault();
            closeModal(settingsDropdown); // Close settings dropdown
            openModal(deleteAllStep1Modal);
        });

        confirmDeleteAllStep1.addEventListener('click', () => {
            closeModal(deleteAllStep1Modal);
            openModal(deleteAllStep2Modal);
        });

        confirmDeleteAllStep2.addEventListener('click', async () => {
            const confirmationText = deleteAllConfirmationInput.value.trim();
            if (confirmationText === "DELETE ALL") {
                deleteAllMessage.textContent = 'Deleting all pages...';
                deleteAllMessage.classList.remove('hidden', 'text-red-600');
                deleteAllMessage.classList.add('text-blue-600'); // Indicate processing

                const formData = new FormData();
                formData.append('action', 'delete_all_user_pages');

                try {
                    const response = await fetch('index.php', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();

                    if (result.status === 'success') {
                        showDeleteAllMessage(result.message, 'success');
                        fetchAllWebsites(searchInput.value, currentTypeFilter, currentLevelFilter, currentSort); // Refresh all pages
                        fetchNotifications(); // Refresh notifications
                        setTimeout(() => closeModal(deleteAllStep3Modal), 2000);
                    } else {
                        showDeleteAllMessage(result.message, 'error');
                    }
                } catch (error) {
                    console.error('Error deleting all pages:', error);
                    showDeleteAllMessage('An unexpected error occurred during deletion.', 'error');
                }
            } else {
                showDeleteAllMessage('Please type "DELETE ALL" correctly to confirm.', 'error');
            }
        });

        function showDeleteAllMessage(message, type) {
            deleteAllMessage.textContent = ''; // Clear previous messages in step 2
            deleteAllFinalMessage.textContent = message;
            if (type === 'success') {
                deleteAllFinalMessage.classList.remove('text-red-600');
                deleteAllFinalMessage.classList.add('text-green-600');
            } else {
                deleteAllFinalMessage.classList.remove('text-green-600');
                deleteAllFinalMessage.classList.add('text-red-600');
            }
            closeModal(deleteAllStep2Modal);
            openModal(deleteAllStep3Modal);
        }
    </script>
</body>
</html>
<?php $mysqli->close(); // Close database connection ?>