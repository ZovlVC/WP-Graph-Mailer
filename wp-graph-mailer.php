<?php
/*
Plugin Name: WP Graph Mailer
Description: Send all wp_mail() via Microsoft Graph (Application permissions). Supports large attachments via upload sessions and shared mailboxes (requires proper Graph/Exchange permissions).
Version: 1.0.0
Author: WP Graph Mailer Team
*/

if (!defined('ABSPATH')) { exit; }

class WP_Graph_Mailer {
    const OPTION_KEY = 'wpgm_options';
    const NONCE      = 'wpgm_settings_nonce';
    const VERSION    = '1.0.0';

    public function __construct() {
        add_filter('pre_wp_mail', [$this, 'intercept_wp_mail'], 10, 2);
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_post_wpgm_send_test', [$this, 'handle_send_test']);
    }

    /* ---------------- Settings ---------------- */

    public function defaults() {
        return [
            'tenant_id'   => '',
            'client_id'   => '',
            'client_secret' => '',
            'from_upn'    => '',
            'chunk_bytes' => 4194304, // 4 MB
            'enabled'     => 1,
        ];
    }

    public function get_options() {
        $opts = get_option(self::OPTION_KEY, []);
        $opts = wp_parse_args($opts, $this->defaults());

        // Allow overriding via constants in wp-config.php if desired.
        if (defined('WPGM_TENANT_ID'))    $opts['tenant_id'] = WPGM_TENANT_ID;
        if (defined('WPGM_CLIENT_ID'))    $opts['client_id'] = WPGM_CLIENT_ID;
        if (defined('WPGM_CLIENT_SECRET'))$opts['client_secret'] = WPGM_CLIENT_SECRET;
        if (defined('WPGM_FROM_UPN'))     $opts['from_upn'] = WPGM_FROM_UPN;
        if (defined('WPGM_CHUNK_BYTES'))  $opts['chunk_bytes'] = (int) WPGM_CHUNK_BYTES;
        if (defined('WPGM_ENABLED'))      $opts['enabled'] = (int) WPGM_ENABLED;

        return $opts;
    }

    public function add_settings_page() {
        add_options_page('WP Graph Mailer', 'WP Graph Mailer', 'manage_options', 'wpgm-settings', [$this, 'render_settings_page']);
    }

    public function register_settings() {
        register_setting(self::OPTION_KEY, self::OPTION_KEY, [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_options'],
            'default' => $this->defaults(),
        ]);
    }

    public function sanitize_options($input) {
        $out = $this->get_options();
        $out['tenant_id'] = sanitize_text_field($input['tenant_id'] ?? '');
        $out['client_id'] = sanitize_text_field($input['client_id'] ?? '');
        // Don't log secrets
        $out['client_secret'] = trim($input['client_secret'] ?? '');
        $out['from_upn'] = sanitize_text_field($input['from_upn'] ?? '');
        $out['chunk_bytes'] = max(1024 * 1024, (int)($input['chunk_bytes'] ?? 4194304)); // >= 1 MB
        $out['enabled'] = isset($input['enabled']) ? 1 : 0;
        return $out;
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) return;
        $opts = $this->get_options();
        ?>
        <div class="wrap">
          <h1>WP Graph Mailer</h1>
          <p>Sendet <code>wp_mail()</code> über Microsoft Graph (Application Permissions). Unterstützt große Anhänge via Upload-Session und Shared Mailbox (richtige Berechtigungen vorausgesetzt).</p>
          <form method="post" action="options.php">
            <?php settings_fields(self::OPTION_KEY); ?>
            <?php $nonce = wp_create_nonce(self::NONCE); ?>
            <input type="hidden" name="<?php echo esc_attr(self::NONCE); ?>" value="<?php echo esc_attr($nonce); ?>" />
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="tenant_id">Tenant ID</label></th>
                    <td><input name="<?php echo self::OPTION_KEY; ?>[tenant_id]" type="text" id="tenant_id" value="<?php echo esc_attr($opts['tenant_id']); ?>" class="regular-text" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="client_id">Client ID (App ID)</label></th>
                    <td><input name="<?php echo self::OPTION_KEY; ?>[client_id]" type="text" id="client_id" value="<?php echo esc_attr($opts['client_id']); ?>" class="regular-text" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="client_secret">Client Secret</label></th>
                    <td><input name="<?php echo self::OPTION_KEY; ?>[client_secret]" type="password" id="client_secret" value="<?php echo esc_attr($opts['client_secret']); ?>" class="regular-text" autocomplete="off"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="from_upn">From (User/Shared Mailbox UPN)</label></th>
                    <td><input name="<?php echo self::OPTION_KEY; ?>[from_upn]" type="text" id="from_upn" value="<?php echo esc_attr($opts['from_upn']); ?>" class="regular-text" placeholder="z.B. rechnung@example.com" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="chunk_bytes">Chunk-Größe (Bytes)</label></th>
                    <td><input name="<?php echo self::OPTION_KEY; ?>[chunk_bytes]" type="number" id="chunk_bytes" value="<?php echo esc_attr($opts['chunk_bytes']); ?>" class="small-text"> <span class="description">Standard 4194304 (4 MB). Mindestens 1048576 (1 MB).</span></td>
                </tr>
                <tr>
                    <th scope="row"><label for="enabled">Aktiv</label></th>
                    <td><label><input name="<?php echo self::OPTION_KEY; ?>[enabled]" type="checkbox" id="enabled" <?php checked($opts['enabled'], 1); ?>> Alle <code>wp_mail()</code>-Aufrufe über Graph senden</label></td>
                </tr>
            </table>
            <?php submit_button(); ?>
          </form>

          <hr />
          <h2>Test-E-Mail</h2>
          <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
            <?php $nonce2 = wp_create_nonce('wpgm_send_test'); ?>
            <input type="hidden" name="action" value="wpgm_send_test" />
            <input type="hidden" name="_wpnonce" value="<?php echo esc_attr($nonce2); ?>" />
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="test_to">An</label></th>
                    <td><input type="email" id="test_to" name="test_to" class="regular-text" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="test_subject">Betreff</label></th>
                    <td><input type="text" id="test_subject" name="test_subject" class="regular-text" value="WP Graph Mailer Test"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="test_message">Nachricht (HTML erlaubt)</label></th>
                    <td><textarea id="test_message" name="test_message" class="large-text" rows="6">Hallo, dies ist ein Test via Microsoft Graph.</textarea></td>
                </tr>
                <tr>
                    <th scope="row"><label for="test_attachment">Anhang (optional)</label></th>
                    <td><input type="file" id="test_attachment" name="test_attachment"></td>
                </tr>
            </table>
            <?php submit_button('Test senden'); ?>
          </form>

          <p><strong>Hinweise:</strong> Die App in Entra ID benötigt <code>Mail.Send</code> und für Shared Mailbox zusätzlich <code>Mail.Send.Shared</code> (Application Permissions, Admin Consent). Beschränke die App auf spezifische Postfächer (Application Access Policy bzw. Exchange RBAC for Applications).</p>
        </div>
        <?php
    }

    public function handle_send_test() {
        if (!current_user_can('manage_options')) wp_die('Unauthorized.');
        check_admin_referer('wpgm_send_test');
        $to      = isset($_POST['test_to']) ? sanitize_email($_POST['test_to']) : '';
        $subject = sanitize_text_field($_POST['test_subject'] ?? 'WP Graph Mailer Test');
        $message = wp_kses_post($_POST['test_message'] ?? 'Hallo von WP Graph Mailer.');

        $attachment_path = null;
        if (!empty($_FILES['test_attachment']['name'])) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            $upload = wp_handle_upload($_FILES['test_attachment'], ['test_form' => false]);
            if (empty($upload['error']) && !empty($upload['file'])) {
                $attachment_path = $upload['file'];
            }
        }

        $headers = ["Content-Type: text/html; charset=UTF-8"];
        $result  = wp_mail($to, $subject, $message, $headers, $attachment_path ? [$attachment_path] : []);

        if ($attachment_path && file_exists($attachment_path)) {
            // Clean up uploaded test file
            @unlink($attachment_path);
        }

        if (is_wp_error($result)) {
            wp_redirect(add_query_arg(['page' => 'wpgm-settings', 'wpgm_test' => 'fail', 'msg' => urlencode($result->get_error_message())], admin_url('options-general.php')));
        } else {
            wp_redirect(add_query_arg(['page' => 'wpgm-settings', 'wpgm_test' => 'ok'], admin_url('options-general.php')));
        }
        exit;
    }

    /* ---------------- Mail Interceptor ---------------- */

    public function intercept_wp_mail($pre, $atts) {
        $opts = $this->get_options();
        if (!$opts['enabled']) return null; // Let WP handle normally
        foreach (['tenant_id','client_id','client_secret','from_upn'] as $k) {
            if (empty($opts[$k])) return null; // Missing config → fallback to default wp_mail
        }

        $to        = $this->normalize_emails($atts['to'] ?? '');
        $subject   = (string) ($atts['subject'] ?? '');
        $message   = (string) ($atts['message'] ?? '');
        $headers   = $this->parse_headers($atts['headers'] ?? []);
        $attachments = $atts['attachments'] ?? [];

        if (empty($to)) return new WP_Error('wpgm_no_to', 'Empfänger (to) fehlt.');

        $is_html = true;
        if (!empty($headers['content-type'])) {
            $ct = implode(' ', (array)$headers['content-type']);
            $is_html = (stripos($ct, 'text/plain') === false);
        }

        try {
            $token = $this->get_access_token($opts['tenant_id'], $opts['client_id'], $opts['client_secret']);
        } catch (Exception $e) {
            return new WP_Error('wpgm_auth', 'Token konnte nicht geholt werden: ' . $e->getMessage());
        }

        $sender = trim($opts['from_upn']);

        // 1) Draft erstellen
        $msg = [
            'subject' => $subject,
            'body'    => [
                'contentType' => $is_html ? 'HTML' : 'Text',
                'content'     => $message,
            ],
            'toRecipients' => array_map([$this, 'mailbox'], $to),
        ];
        if (!empty($headers['cc']))  $msg['ccRecipients']  = array_map([$this, 'mailbox'], $this->normalize_emails($headers['cc']));
        if (!empty($headers['bcc'])) $msg['bccRecipients'] = array_map([$this, 'mailbox'], $this->normalize_emails($headers['bcc']));

        $draft_resp = $this->graph_request('POST', "https://graph.microsoft.com/v1.0/users/" . rawurlencode($sender) . "/messages", $msg, [
            'Authorization' => 'Bearer ' . $token,
            'Content-Type'  => 'application/json',
        ], 30);

        if (is_wp_error($draft_resp)) return $draft_resp;
        $code = wp_remote_retrieve_response_code($draft_resp);
        $body = json_decode(wp_remote_retrieve_body($draft_resp), true);
        if ($code < 200 || $code >= 300 || empty($body['id'])) {
            return new WP_Error('wpgm_draft', 'Draft konnte nicht erstellt werden. Code ' . $code . ' Antwort: ' . wp_remote_retrieve_body($draft_resp));
        }
        $message_id = $body['id'];

        // 2) Anhänge hinzufügen
        $max_inline = 3 * 1024 * 1024; // 3 MB
        $chunk_bytes = (int)$opts['chunk_bytes'];
        $chunk_bytes = max(1024*1024, $chunk_bytes);

        $attachments = is_array($attachments) ? $attachments : (empty($attachments) ? [] : [$attachments]);
        foreach ($attachments as $path) {
            if (!$path) continue;
            if (!file_exists($path)) {
                return new WP_Error('wpgm_attach_missing', 'Anhang nicht gefunden: ' . $path);
            }
            $size = filesize($path);
            $name = wp_basename($path);
            $type = $this->detect_mime($path);

            if ($size <= $max_inline) {
                // Klein: Base64-Upload
                $payload = [
                    '@odata.type' => '#microsoft.graph.fileAttachment',
                    'name'        => $name,
                    'contentType' => $type,
                    'contentBytes'=> base64_encode(file_get_contents($path)),
                ];
                $a_resp = $this->graph_request('POST',
                    "https://graph.microsoft.com/v1.0/users/" . rawurlencode($sender) . "/messages/" . rawurlencode($message_id) . "/attachments",
                    $payload,
                    ['Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json'],
                    60
                );
                if (is_wp_error($a_resp) || wp_remote_retrieve_response_code($a_resp) >= 300) {
                    return new WP_Error('wpgm_attach_small', 'Kleiner Anhang konnte nicht hinzugefügt werden: ' . wp_remote_retrieve_body($a_resp));
                }
            } else {
                // Groß: Upload-Session
                $session_body = [
                    'AttachmentItem' => [
                        'attachmentType' => 'file',
                        'name'           => $name,
                        'size'           => (int)$size,
                        'contentType'    => $type,
                    ],
                ];
                $s_resp = $this->graph_request('POST',
                    "https://graph.microsoft.com/v1.0/users/" . rawurlencode($sender) . "/messages/" . rawurlencode($message_id) . "/attachments/createUploadSession",
                    $session_body,
                    ['Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json'],
                    30
                );
                if (is_wp_error($s_resp)) return $s_resp;
                $code = wp_remote_retrieve_response_code($s_resp);
                $s_body = json_decode(wp_remote_retrieve_body($s_resp), true);
                if ($code < 200 || $code >= 300 || empty($s_body['uploadUrl'])) {
                    return new WP_Error('wpgm_upload_session', 'Upload-Session fehlgeschlagen: ' . wp_remote_retrieve_body($s_resp));
                }
                $upload_url = $s_body['uploadUrl'];

                $fh = fopen($path, 'rb');
                if (!$fh) return new WP_Error('wpgm_fopen', 'Datei konnte nicht geöffnet werden: ' . $path);
                $start = 0;
                while (!feof($fh)) {
                    $data = fread($fh, $chunk_bytes);
                    if ($data === false) { fclose($fh); return new WP_Error('wpgm_read', 'Lesefehler bei: ' . $path); }
                    $len  = strlen($data);
                    $end  = $start + $len - 1;
                    $headers = [
                        'Content-Length' => $len,
                        'Content-Range'  => 'bytes ' . $start . '-' . $end . '/' . $size,
                    ];
                    // PUT to pre-authenticated uploadUrl
                    $u_resp = wp_remote_request($upload_url, [
                        'method'  => 'PUT',
                        'timeout' => 120,
                        'headers' => $headers,
                        'body'    => $data,
                    ]);
                    $status = is_wp_error($u_resp) ? 0 : wp_remote_retrieve_response_code($u_resp);
                    if (is_wp_error($u_resp) || ($status < 200 || $status >= 400)) {
                        fclose($fh);
                        return new WP_Error('wpgm_chunk', 'Chunk-Upload fehlgeschlagen (Status ' . $status . '): ' . (is_wp_error($u_resp) ? $u_resp->get_error_message() : wp_remote_retrieve_body($u_resp)));
                    }
                    $start += $len;
                }
                fclose($fh);
            }
        }

        // 3) Senden
        $send_resp = $this->graph_request('POST',
            "https://graph.microsoft.com/v1.0/users/" . rawurlencode($sender) . "/messages/" . rawurlencode($message_id) . "/send",
            null,
            ['Authorization' => 'Bearer ' . $token],
            30
        );

        if (is_wp_error($send_resp)) return $send_resp;
        $send_code = wp_remote_retrieve_response_code($send_resp);
        if ($send_code < 200 || $send_code >= 300) {
            return new WP_Error('wpgm_send', 'Senden fehlgeschlagen: HTTP ' . $send_code . ' ' . wp_remote_retrieve_body($send_resp));
        }

        return true; // short-circuit wp_mail()
    }

    private function mailbox($email) {
        return ['emailAddress' => ['address' => trim($email)]];
    }

    private function normalize_emails($v) {
        if (is_array($v)) { $arr = $v; }
        else { $arr = preg_split('/[,;]+/', (string)$v); }
        $out = [];
        foreach ($arr as $e) {
            $e = trim($e);
            if ($e) $out[] = $e;
        }
        return $out;
    }

    private function parse_headers($headers) {
        $out = [];
        if (empty($headers)) return $out;

        if (is_array($headers)) {
            foreach ($headers as $h) {
                $this->parse_header_line($out, $h);
            }
        } else {
            foreach (preg_split("/(\r?\n)/", (string)$headers) as $h) {
                $this->parse_header_line($out, $h);
            }
        }
        return $out;
    }

    private function parse_header_line(&$out, $line) {
        if (strpos($line, ':') === false) return;
        list($name, $value) = array_map('trim', explode(':', $line, 2));
        $key = strtolower($name);
        if (!isset($out[$key])) $out[$key] = [];
        $out[$key][] = trim($value);
    }

    private function detect_mime($path) {
        $type = function_exists('mime_content_type') ? mime_content_type($path) : false;
        if (!$type) {
            $ft = wp_check_filetype($path);
            $type = $ft['type'] ?: 'application/octet-stream';
        }
        return $type;
    }

    /* ---------------- Graph helpers ---------------- */

    private function get_access_token($tenant_id, $client_id, $client_secret) {
        $cache_key = 'wpgm_tok_' . md5($tenant_id . '|' . $client_id);
        $cached = get_transient($cache_key);
        if (is_array($cached) && !empty($cached['access_token']) && time() < $cached['exp']) {
            return $cached['access_token'];
        }

        $resp = wp_remote_post("https://login.microsoftonline.com/" . rawurlencode($tenant_id) . "/oauth2/v2.0/token", [
            'timeout' => 30,
            'body' => [
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'scope' => 'https://graph.microsoft.com/.default',
                'grant_type' => 'client_credentials',
            ],
        ]);
        if (is_wp_error($resp)) throw new Exception($resp->get_error_message());
        $code = wp_remote_retrieve_response_code($resp);
        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if ($code < 200 || $code >= 300 || empty($body['access_token'])) {
            throw new Exception('Token HTTP ' . $code . ' ' . wp_remote_retrieve_body($resp));
        }
        $ttl = isset($body['expires_in']) ? (int)$body['expires_in'] : 3599;
        set_transient($cache_key, ['access_token' => $body['access_token'], 'exp' => time() + max(60, $ttl - 60)], $ttl);
        return $body['access_token'];
    }

    private function graph_request($method, $url, $json_body = null, $headers = [], $timeout = 30) {
        $args = [
            'method'  => $method,
            'timeout' => $timeout,
            'headers' => $headers,
        ];
        if (!is_null($json_body)) {
            $args['body'] = is_string($json_body) ? $json_body : wp_json_encode($json_body);
            if (empty($headers['Content-Type'])) {
                $args['headers']['Content-Type'] = 'application/json';
            }
        }
        $resp = wp_remote_request($url, $args);
        if (is_wp_error($resp)) return $resp;
        return $resp;
    }
}

new WP_Graph_Mailer();
