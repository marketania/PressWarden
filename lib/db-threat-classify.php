<?php
/* Pure classifiers for WordPress database threat intelligence. */
function presswarden_db_clean($v) {
    return trim(preg_replace('/[\r\n\t]+/', ' ', (string)$v));
}

function presswarden_db_classify_content($value, $source, $name = '') {
    $v = (string)$value;
    $source = (string)$source;
    $name = (string)$name;
    $externalScript = (bool)preg_match('~<script\b[^>]+src\s*=\s*[\'\"]?https?://~i', $v);
    $dynamicScript = (bool)preg_match('~createElement\s*\(\s*[\'\"]script[\'\"]~i', $v)
        && (bool)preg_match('~(?:\.src\s*=|setAttribute\s*\(\s*[\'\"]src[\'\"])~i', $v);
    $decode = (bool)preg_match('~\b(?:atob|String\.fromCharCode|decodeURIComponent|unescape)\s*\(~i', $v);
    $execJs = (bool)preg_match('~\b(?:eval|Function)\s*\(~i', $v);
    $hiddenIframe = (bool)preg_match('~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'\"]?0|height\s*=\s*[\'\"]?0)[^>]*https?://~i', $v)
        || ((bool)preg_match('~<iframe\b[^>]+https?://~i', $v)
            && (bool)preg_match('~display\s*:\s*none|visibility\s*:\s*hidden~i', $v));
    if (($externalScript || $dynamicScript) && ($decode || $execJs)) return ['ALERT', 'PW-DB-001'];
    if ($hiddenIframe) return ['ALERT', 'PW-DB-002'];

    $phpTag = stripos($v, '<?php') !== false;
    $request = (bool)preg_match('~\$_(?:GET|POST|REQUEST|COOKIE)\b~', $v);
    $execPhp = (bool)preg_match('~\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(~i', $v);
    $decodePhp = (bool)preg_match('~\b(?:base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|hex2bin|openssl_decrypt)\s*\(~i', $v);
    if ($phpTag && $execPhp && ($request || $decodePhp)) return ['REVIEW', 'PW-DB-005'];

    if ($source === 'option' && preg_match('~^[a-f0-9]{32}$~i', $name)) {
        $longEncoded = (bool)preg_match('~(?:[A-Za-z0-9+/]{120,}={0,2}|(?:[0-9a-fA-F]{2}){80,})~', $v);
        $urls = substr_count(strtolower($v), 'http://') + substr_count(strtolower($v), 'https://');
        if ($longEncoded || $urls >= 2) return ['REVIEW', 'PW-DB-006'];
    }

    if ($source === 'option' && ($externalScript || $dynamicScript)) return ['REVIEW', 'PW-DB-003'];
    return null;
}

function presswarden_db_classify_admin($login, $email) {
    $login = trim((string)$login);
    $email = trim((string)$email);
    $lowerLogin = strtolower($login);
    $lowerEmail = strtolower($email);
    if ($lowerLogin === 'adminbackup' && $lowerEmail === 'adminbackup@wordpress.org') {
        return ['ALERT', 'PW-DB-004', 'documented disguised-plugin administrator identity'];
    }
    if (preg_match('~^[a-f0-9]{24,64}$~i', $login)) {
        $local = strtolower((string)strtok($email, '@'));
        if ($local === $lowerLogin || preg_match('~^[a-f0-9]{24,64}$~', $local)) {
            return ['REVIEW', 'PW-DB-004', 'hex-like administrator login and email identity'];
        }
    }
    return null;
}
