<?php
/** Contextual, read-only database threat classifiers. Stored code is never run. */
require_once __DIR__.'/db-values.php';
require_once __DIR__.'/js-flow.php';
function presswarden_db_clean($v) {
    return preg_replace_callback('~[\x00-\x1f\x7f]~', function ($m) { return sprintf('\\x%02X', ord($m[0])); }, (string)$v);
}

/** Parse attributes as data. Ignore names embedded in other attribute values. */
function presswarden_db_attributes($text) {
    $attrs = [];
    preg_match_all('~([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+)))?~', $text, $matches, PREG_SET_ORDER);
    foreach ($matches as $m) {
        $key = strtolower($m[1]);
        if (array_key_exists($key, $attrs)) continue; // HTML uses first attribute.
        $attrs[$key] = html_entity_decode($m[2] ?? $m[3] ?? $m[4] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // preg_match pads unmatched alternatives with empty strings.
        if (isset($m[3]) && $m[3] !== '') $attrs[$key] = html_entity_decode($m[3], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if (isset($m[4]) && $m[4] !== '') $attrs[$key] = html_entity_decode($m[4], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    return $attrs;
}

function presswarden_db_remote($url) {
    return is_string($url) && (bool)preg_match('~^(?:https?:)?//[^\s/]+~i', trim($url));
}

/** Small markup reader: raw-text blocks and nested templates stay inert.
 * It is not a browser DOM parser; unclosed candidate script blocks are incomplete.
 */
function presswarden_db_markup($source) {
    $js = []; $frames = []; $external = false; $offset = 0; $template = 0; $tags = 0;
    $pattern = '~<!--[\s\S]*?(?:-->|$)|<(/?)([A-Za-z][A-Za-z0-9:-]*)\b((?:"[^"]*"|\'[^\']*\'|[^\'">])*)>~';
    while (preg_match($pattern, $source, $m, PREG_OFFSET_CAPTURE, $offset)) {
        if (++$tags > 12000) throw new RuntimeException('markup_budget');
        $offset = $m[0][1] + strlen($m[0][0]);
        if (substr($m[0][0], 0, 4) === '<!--') continue;
        $closing = $m[1][0] === '/'; $tag = strtolower($m[2][0]);
        if ($tag === 'template') { $template = max(0, $template + ($closing ? -1 : 1)); continue; }
        if ($closing) continue;
        $attrs = presswarden_db_attributes($m[3][0]);
        if (in_array($tag, ['script','style','textarea','title','xmp','iframe','noembed','noframes'], true)) {
            $end = preg_match('~</'. $tag .'\s*>~i', $source, $close, PREG_OFFSET_CAPTURE, $offset);
            if (!$end && $tag === 'script') throw new RuntimeException('markup_format');
            $body = $end ? substr($source, $offset, $close[0][1]-$offset) : '';
            $offset = $end ? $close[0][1]+strlen($close[0][0]) : strlen($source);
            if ($template > 0) continue;
            if ($tag === 'script') {
                $type = strtolower(trim(explode(';', $attrs['type'] ?? '')[0]));
                if (!in_array($type, ['', 'module','text/javascript','application/javascript','text/ecmascript','application/ecmascript'], true)) continue;
                if (isset($attrs['src'])) { if (presswarden_db_remote($attrs['src'])) $external = true; }
                else $js[] = $body;
            } elseif ($tag === 'iframe') $frames[] = $attrs;
        }
    }
    return [$js, $frames, $external];
}

function presswarden_db_php_expression($source) {
    if (strpos($source, '<?') === false) return false;
    $tokens = token_get_all($source); $code = []; $quoted = false; $heredoc = false;
    foreach ($tokens as $t) {
        if (is_array($t) && $t[0] === T_START_HEREDOC) { $heredoc = true; continue; }
        if ($heredoc) { if (is_array($t) && $t[0] === T_END_HEREDOC) $heredoc = false; continue; }
        if ($t === '"' || $t === '`') { $quoted = !$quoted; continue; }
        if ($quoted) continue;
        if (is_array($t) && in_array($t[0], [T_COMMENT, T_DOC_COMMENT, T_WHITESPACE], true)) continue;
        $code[] = $t;
    }
    if ($quoted || $heredoc || count($code) > 120000) throw new RuntimeException('value_budget');
    foreach ($code as $i => $t) {
        if (!is_array($t) || !in_array(strtolower($t[1]), ['eval','assert','system','exec','shell_exec','passthru','popen','proc_open'], true)) continue;
        if (!in_array($t[0], [T_EVAL, T_STRING], true) || ($code[$i+1] ?? '') !== '(') continue;
        $prev = $code[$i-1] ?? '';
        if (is_array($prev) && in_array($prev[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true)) continue;
        $depth = 1; $signal = false;
        for ($j=$i+2; isset($code[$j]) && $j<$i+2048; ++$j) {
            $a = $code[$j]; if ($a === '(') ++$depth;
            if ($a === ')' && --$depth === 0) { if ($signal) return true; break; }
            if ($a === ';' || $a === '{' || $depth > 16) break;
            if (!is_array($a)) continue;
            if ($a[0] === T_VARIABLE && in_array($a[1], ['$_GET','$_POST','$_REQUEST','$_COOKIE'], true)) $signal = true;
            if ($a[0] === T_STRING && in_array(strtolower($a[1]), ['base64_decode','gzinflate','gzdecode','gzuncompress','str_rot13','hex2bin','openssl_decrypt'], true)
                && ($code[$j+1] ?? '') === '(') $signal = true;
        }
    }
    return false;
}

/** Findings remain independent per stored string, script block and iframe. */
function presswarden_db_classify_all($value, $source, $name = '') {
    $found = []; $scanner = new PressWardenJsFlow();
    $add = function ($kind, $rule) use (&$found) {
        if (($found[$rule][0] ?? '') !== 'ALERT') $found[$rule] = [$kind, $rule];
    };
    foreach (presswarden_db_units($value) as $unit) {
        $encodedOption = false;
        if ($source === 'option' && preg_match('~^[a-f0-9]{32}$~i', $name) && preg_match('~^[A-Za-z0-9+/]{120,}={0,2}$~D', $unit)) {
            $decoded = base64_decode($unit, true);
            if (is_string($decoded)) { $unit = $decoded; $encodedOption = true; }
        }
        [$jsUnits, $frames, $external] = presswarden_db_markup($unit);
        foreach ($frames as $attrs) {
            $hidden = preg_match('~(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:;|$)~i', $attrs['style'] ?? '')
                || ($attrs['width'] ?? '') === '0' || ($attrs['height'] ?? '') === '0';
            if (!$hidden || !presswarden_db_remote($attrs['src'] ?? '')) continue;
            foreach (['onload','onerror'] as $event) {
                if (!isset($attrs[$event])) continue;
                foreach ($scanner->scan($attrs[$event]) as $hit) $add('REVIEW', 'PW-DB-002');
            }
        }
        // Plain code is considered only when it is not HTML or stored PHP.
        if (!preg_match('~<[/!?A-Za-z]~', $unit)) $jsUnits[] = $unit;
        foreach ($jsUnits as $js) {
            if (!preg_match('~\b(?:atob|fromCharCode|decodeURIComponent|unescape)\s*\(~', $js)) continue;
            foreach ($scanner->scan($js) as $hit) $add($encodedOption ? 'REVIEW' : $hit['kind'], $encodedOption ? 'PW-DB-006' : 'PW-DB-001');
        }
        if (presswarden_db_php_expression($unit)) $add('REVIEW', 'PW-DB-005');
        // Preserve the existing site-wide custom-code review, not a malware
        // verdict. Ordinary post embeds and unrelated widget values stay clean.
        if ($source === 'option' && $external && preg_match('~^(?:header_scripts|footer_scripts|custom_scripts|custom_js)$~i', $name)) $add('REVIEW', 'PW-DB-003');
    }
    return array_values($found);
}

// Compatibility interface for existing callers; keep the strongest first match.
function presswarden_db_classify_content($value, $source, $name = '') {
    $found = presswarden_db_classify_all($value, $source, $name);
    foreach ($found as $hit) if ($hit[0] === 'ALERT') return $hit;
    return $found[0] ?? null;
}

function presswarden_db_classify_admin($login, $email) {
    $login = trim((string)$login);
    $email = trim((string)$email);
    $lowerLogin = strtolower($login);
    $lowerEmail = strtolower($email);
    if ($lowerLogin === 'adminbackup' && $lowerEmail === 'adminbackup@wordpress.org') {
        return ['REVIEW', 'PW-DB-004', 'identity matches published persistence indicator; ownership unverified'];
    }
    if (preg_match('~^[a-f0-9]{24,64}$~i', $login)) {
        $local = strtolower((string)strtok($email, '@'));
        if ($local === $lowerLogin || preg_match('~^[a-f0-9]{24,64}$~', $local)) {
            return ['REVIEW', 'PW-DB-004', 'hex-like administrator login and email identity'];
        }
    }
    return null;
}
