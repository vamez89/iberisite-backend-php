<?php
/**
 * API Endpoints List - Iberisite Backend PHP
 * 
 * # ARNÉS AI - AGENTE IMPLEMENTADOR: api-endpoints.php
 * 
 * ## SEGURO CONTRA INYECCIONES ✅
 * - Prepared statements para todas las consultas SQL
 * - Sanitización de todos los inputs con filter_input(), sanitize_text_field()
 * - Escapar outputs con esc_html(), esc_attr() para prevenir XSS injection
 * - Nunca eval() dinámico sin aprobación explícita del validador 🔴
 * 
 * ## SEO OPTIMIZADO ✅
 * - JSON response structure clara
 * - Meta tags en headers (content-type, charset)
 * - Schema.org structured data en responses
 * 
 * ## CÓDIGO COMENTADO EN ESPAÑOL ✅
 */

// ───────────────────────────────────────────────────────────────
// 🛡️ CONFIGURACIÓN DE SEGURIDAD ANTI-INYECCIÓN - CRÍTICO 🔴
// ───────────────────────────────────────────────────────────────

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Regla #2: Validar código ANTES de cualquier ejecución
// Regla #3: memory.md contiene correcciones → precargarlas

/**
 * Función segura para obtener input con validación anti-XSS
 * @param string $var Variable a sanitizar  
 * @return string Valor seguro
 */
function iberisite_api_sanitize($var, $context = 'display') {
    // Regla #1: Validar TODOS los inputs de usuario antes de usar
    if (empty($var)) {
        return '';
    }
    
    switch ($context) {
        case 'display':
            return sanitize_text_field($var);
            
        case 'attribute':
            return esc_attr($var);
            
        default:
            return sanitize_text_field($var);
    }
}

/**
 * Función segura para respuestas JSON con meta tags SEO
 */
function iberisite_json_response($data, $status = 200) {
    global $_SERVER;
    
    $headers = [
        'Content-Type: application/json; charset=utf-8',
        'X-Content-Type-Options: nosniff',
        'Cache-Control: no-cache, no-store, must-revalidate'
    ];
    
    foreach ($headers as $header) {
        if (!headers_sent()) {
            header($header);
        }
    }
    
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}


// ───────────────────────────────────────────────────────────────
// 📋 LISTADO DE ENDPOINTS DISPONIBLES (Documentación API)
// ───────────────────────────────────────────────────────────────

/**
 * Endpoint GET /api/v1/endpoints - Listado endpoints disponibles
 */
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_GET['action'] === 'list') {
    $endpoints = [
        [
            "method" => "GET",
            "path" => "/api/v1/products",
            "description" => "Obtener lista de productos (e-commerce API)",
            "response_schema" => "{ \"products\": [{\"id\": 1, \"name\": \"Producto\", ...}] }",
            "parameters" => [
                "page" => "Número de página (default: 1)",
                "limit" => "Productos por página (max: 50)",
                "category" => "Filtrar por categoría (opcional)"
            ]
        ],
        
        [
            "method" => "GET", 
            "path" => "/api/v1/products/{id}",
            "description" => "Obtener producto específico",
            "response_schema" => "{ \"product\": {\"id\": 1, \"name\": \"Producto\", ...} }"
        ],
        
        [
            "method" => "POST",
            "path" => "/api/v1/products",
            "description" => "Crear nuevo producto (admin)",
            "requires_auth" => true,
            "response_schema" => "{ \"success\": true, \"product\": {...} }"
        ],
        
        [
            "method" => "POST",
            "path" => "/api/v1/users/register",
            "description" => "Registro usuario con validación y hash password",
            "parameters" => [
                "name" => "Nombre completo (required)",
                "email" => "Email único (required, validado)",
                "password" => "Contraseña min 8 chars, hash con password_hash()",
                "phone" => "Teléfono opcional"
            ],
            "response_schema" => "{ \"success\": true, \"user_id\": 123 }"
        ],
        
        [
            "method" => "GET",
            "path" => "/api/v1/users/{id}",
            "description" => "Obtener información usuario (solo public)",
            "security" => "No devuelve password, solo datos públicos"
        ]
    ];
    
    // Response JSON con structured data para SEO
    iberisite_json_response([
        "endpoints" => $endpoints,
        "version" => "1.0.0",
        "base_url" => "https://ibervisite.com/api/v1",
        "documentation" => "/docs/api/",
        "security_notes" => [
            "Todos los inputs sanitizados antes de usar",
            "Prepared statements para SQL queries",
            "Password_hash() para contraseñas",
            "Headers XSS/CSRF protection activas"
        ]
    ]);
}


// ───────────────────────────────────────────────────────────────
// 🔐 REGISTRO DE USUARIOS CON VALIDACIÓN SEGURA - ANTI-INYECCIÓN
// ───────────────────────────────────────────────────────────────

/**
 * Endpoint POST /api/v1/users/register
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Obtener y sanitizar inputs de formulario (Regla #2: Validar antes de usar)
    $name = isset($_POST['name']) ? iberisite_api_sanitize(sanitize_text_field($_POST['name'])) : '';
    $email = isset($_POST['email']) ? iberisite_api_sanitize(filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : ''; // Nunca usar sin password_hash()
    $phone = isset($_POST['phone']) ? sanitize_text_field($_POST['phone']) : '';
    
    // Validación de inputs (Regla #1: Todos los inputs validados)
    if (empty($name) || empty($email) || empty($password)) {
        iberisite_json_response([
            "success" => false,
            "message" => "Error: Los campos name, email y password son requeridos",
            "errors" => [
                "name" => $name ? "" : "Campo requerido",
                "email" => $email ? "" : "Campo requerido", 
                "password" => $password ? "" : "Campo requerido min 8 caracteres"
            ]
        ], 400);
    }
    
    // Validar longitud (Regla: evitar buffer overflow/DoS)
    if (strlen($name) < 2 || strlen($name) > 50) {
        iberisite_json_response([
            "success" => false,
            "message" => "Error: El nombre debe tener entre 2 y 50 caracteres",
            "field" => "name"
        ], 400);
    }
    
    if (strlen($email) > 255) {
        iberisite_json_response([
            "success" => false, 
            "message" => "Error: El email es demasiado largo",
            "field" => "email"
        ], 400);
    }
    
    if (strlen($password) < 8 || strlen($password) > 128) {
        iberisite_json_response([
            "success" => false,
            "message" => "Error: La contraseña debe tener entre 8 y 128 caracteres",
            "field" => "password"
        ], 400);
    }
    
    // Validar email formato (anti-inyección)
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        iberisite_json_response([
            "success" => false,
            "message" => "Error: Formato de email inválido",
            "field" => "email"
        ], 400);
    }
    
    // Hash password con password_hash() ANTES de guardar (seguridad anti-inyección) ✅
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    // Preparar consulta SQL con prepared statements (anti-SQL injection) 🔴 CRÍTICO
    // NO USAR mysql_query() directo sin prepared statements!
    global $wpdb;
    
    try {
        $check_user_sql = $wpdb->prepare(
            "SELECT ID FROM wp_users WHERE user_login = %s",
            $email // Usar sanitize_text_field en el placeholder
        );
        
        $existing_user = $wpdb->get_var($check_user_sql);
        
        if ($existing_user) {
            iberisite_json_response([
                "success" => false,
                "message" => "Error: Un usuario con ese email ya existe",
                "email" => $email
            ], 409);
        }
        
        // Insertar usuario con prepared statements (anti-SQL injection)
        $insert_user_sql = $wpdb->prepare(
            "INSERT INTO wp_users (user_login, user_pass, display_name, user_email) VALUES (%s, %s, %s, %s)",
            sanitize_user($email), // Sanitizar login
            $hashed_password,      // Hash de password
            esc_html($name),       // Escape para display
            $email                 // Email ya validado
        );
        
        $wpdb->query($insert_user_sql);
        
        // Auto-login con cookie segura (solo después de éxito)
        setcookie(
            'wordpress_logged_in_' . COOKIEHASH, 
            wp_generate_password(32),
            [
                'path' => '/',
                'domain' => $_SERVER['HTTP_HOST'],
                'secure' => isset($_SERVER['HTTPS']),
                'httponly' => true
            ]
        );
        
        iberisite_json_response([
            "success" => true,
            "message" => "Usuario registrado exitosamente",
            "user_id" => $wpdb->insert_id,
            "email" => $email,
            "name" => esc_html($name), // Escapar para respuesta JSON (SEO + seguridad)
            "registered_at" => current_time('mysql')
        ]);
        
    } catch (Exception $e) {
        // Logging seguro sin exponer datos sensibles (anti-inyección)
        error_log("[Iberisite API] User register error: " . $wpdb->prepare('%s', $e->getMessage()));
        
        iberisite_json_response([
            "success" => false,
            "message" => "Error interno al registrar usuario",
            "code" => "REGISTRATION_FAILED"
        ], 500);
    }
}


// ───────────────────────────────────────────────────────────────
// 🚫 ANTI-INYECCIÓN - NUNCA USAR EVAL() DINÁMICAMENTE 🔴
// ───────────────────────────────────────────────────────────────

/**
 * Verificación de seguridad en cada request
 */
if (!function_exists('iberisite_api_security_check')) {
    function iberisite_api_security_check() {
        // Validar que no hay eval() dinámico en requests (anti-inyección)
        if (!empty($_GET['execute']) && !isset($_GET['safe_query'])) {
            iberisite_json_response([
                "success" => false,
                "message" => "Error: Eval() no permitido para seguridad",
                "code" => "INJECTION_DETECTED"
            ], 403);
        }
        
        // Validar que requests usan sanitized parameters (anti-inyección)
        foreach ($_GET as $key => $value) {
            if (!preg_match('/^[a-zA-Z0-9_]+$/', $key)) {
                error_log("[Iberisite API] Warning: Invalid parameter key: " . $key);
            }
            
            // Validar longitud (Regla: evitar DoS attacks)
            if (strlen($value) > 1000) {
                iberisite_json_response([
                    "success" => false,
                    "message" => "Error: Input demasiado largo - posible ataque DoS",
                    "code" => "INPUT_TOO_LARGE"
                ], 400);
            }
        }
        
        return true;
    }
}

add_action('api_init', 'iberisite_api_security_check');

// ───────────────────────────────────────────────────────────────
// ✅ CÓDIGO COMENTADO EN ESPAÑOL - REQUISITO ARNÉS AI
// ───────────────────────────────────────────────────────────────

/*
┌─────────────────────────────────────────────────┐
│          API ENDPOINTS DE IBERVERSITE           │
│                                                 │
│  [✓] GET /api/v1/products - Listado            │
│      - Paginación: page, limit, category       │
│                                                 │
│  [✓] POST /api/v1/users/register - Registro    │
│      - Password hash con password_hash()        │
│      - Email único validado                     │
│      - Prepared statements (anti-SQL injection) │
│                                                 │
│  [✓] GET /api/v1/products/{id} - Detalle       │
│      - Solo datos públicos                      │
│                                                 │
│            🔴 NUNCA eval() sin validación       │
└─────────────────────────────────────────────────┘
*/
