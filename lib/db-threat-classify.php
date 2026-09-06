<?php
/**
 * PressWarden database threat-intelligence classifiers.
 *
 * Pure classification helpers only: no database access, no output, and no
 * remediation. Keeping these functions independent from WordPress makes the
 * behavioral rules directly regression-testable without a live database.
 */

function presswarden_db_classify_content($value, $source)
{
    $value = (string) $value;
    $source = (string) $source;

    $externalScript = (bool) preg_match('~<script\b[^>]+src\s*=\s*[\'\"]?https?://~i', $value);
    $dynamicScript = (bool) preg_match('~createElement\s*\(\s*[\'\"]script[\'\"]~i', $value)
        && (bool) preg_match('~(?:\.src\s*=|setAttribute\s*\(\s*[\'\"]src[\'\"])~i', $value);
    $decode = (bool) preg_match('~\b(?:atob|String\.fromCharCode|decodeURIComponent|unescape)\s*\(~i', $value);
    $exec = (bool) preg_match('~\b(?:eval|Function)\s*\(~i', $value);
    $hiddenIframe = (bool) preg_match(
        '~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'\"]?0|height\s*=\s*[\'\"]?0)[^>]*https?://~i',
        $value
    ) || (
        (bool) preg_match('~<iframe\b[^>]+https?://~i', $value)
        && (bool) preg_match('~display\s*:\s*none|visibility\s*:\s*hidden~i', $value)
    );

    if (($externalScript || $dynamicScript) && ($decode || $exec)) {
        return array('ALERT', 'PW-DB-001');
    }
    if ($hiddenIframe) {
        return array('ALERT', 'PW-DB-002');
    }
    if ($source === 'option' && ($externalScript || $dynamicScript)) {
        return array('REVIEW', 'PW-DB-003');
    }

    return null;
}

/**
 * Detect a persistence pattern documented in WordPress redirect/reinfector
 * campaigns: a long hexadecimal option key whose Base64 payload reconstructs
 * a list of remote nodes. A hashed option name or Base64 value alone is never
 * a finding; at least two distinct HTTP(S) hosts must be recovered.
 */
function presswarden_db_classify_hex_remote_option($name, $value)
{
    $name = trim((string) $name);
    if (!preg_match('/^[a-f0-9]{24,40}$/i', $name)) {
        return null;
    }

    $compact = preg_replace('/\s+/', '', (string) $value);
    if (!is_string($compact) || strlen($compact) < 80 || strlen($compact) > 262144) {
        return null;
    }
    if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $compact)) {
        return null;
    }

    $decoded = base64_decode($compact, true);
    if ($decoded === false || strlen($decoded) < 32) {
        return null;
    }

    $matches = array();
    $count = preg_match_all('~https?://[a-z0-9][a-z0-9._-]+(?:/[^\s\'\"<>]*)?~i', $decoded, $matches);
    if (!$count || empty($matches[0])) {
        return null;
    }

    $hosts = array();
    foreach ($matches[0] as $url) {
        $host = parse_url($url, PHP_URL_HOST);
        if (is_string($host) && $host !== '') {
            $hosts[strtolower($host)] = true;
        }
    }

    if (count($hosts) >= 2) {
        return array('ALERT', 'PW-DB-004');
    }

    return null;
}

/**
 * Detect the high-specificity rogue-admin identity pattern seen in redirect
 * reinfectors: administrator capability + the same long hexadecimal value as
 * both user_login and the email local-part. Email domains and passwords are
 * intentionally irrelevant and are never returned by this classifier.
 */
function presswarden_db_classify_admin($login, $email, $capabilities)
{
    $login = strtolower(trim((string) $login));
    $email = strtolower(trim((string) $email));
    $capabilities = (string) $capabilities;

    if (!preg_match('/^[a-f0-9]{24,40}$/', $login)) {
        return null;
    }
    if (!preg_match('/^([a-f0-9]{24,40})@[^@]+$/', $email, $m) || $m[1] !== $login) {
        return null;
    }
    if (!preg_match('~"administrator"\s*;\s*b:1\b~i', $capabilities)) {
        return null;
    }

    return array('ALERT', 'PW-DB-005');
}
