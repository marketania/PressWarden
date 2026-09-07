<?php
/**
 * PressWarden native PHP evidence recognizer (MIT, PHP 7.4+).
 * Tokenizes input as data. Never includes, evaluates, or requests site code.
 * Deliberately limited to simple, ordered, intraprocedural expressions.
 */
final class PressWardenPhpFlow {
    const REQUEST = 1, LOGIN = 2, PASSWORD = 4, UA = 8, REMOTE = 16, DECODED = 32;
    private $tokens = [], $findings = [], $handles = [], $nextHandle = 0;
    private $context = 0, $depth = 0, $expressions = 0;

    private function text($t) { return is_array($t) ? $t[1] : $t; }
    private function id($t) { return is_array($t) ? $t[0] : 0; }
    private function line($t) { return is_array($t) ? $t[2] : 1; }
    private function fact($bits = 0, $literal = null, $handle = null) {
        return ['bits'=>$bits, 'literal'=>$literal, 'handle'=>$handle];
    }
    private function emit($rule, $line, $sink) {
        // Evidence never contains credential values, URL bodies, or source text.
        if (isset($this->findings[$rule])) return;
        $this->findings[$rule] = ['rule'=>$rule, 'line'=>$line,
            'kind'=>$rule === 'PW-PHP-006' ? 'REVIEW' : 'ALERT', 'evidence'=>$sink];
    }
    public function scan($source) {
        $this->tokens = $this->findings = $this->handles = [];
        $this->nextHandle = $this->context = $this->depth = 0;
        if (strlen($source) > 5 * 1024 * 1024) throw new RuntimeException('PHP file-size limit');
        $raw = token_get_all($source); $quoted = false; $heredoc = false;
        foreach ($raw as $t) {
            $id = $this->id($t); $text = $this->text($t);
            if ($id === T_START_HEREDOC) { $heredoc = true; $this->tokens[] = [T_STRING, '__pw_unknown_string', $this->line($t)]; continue; }
            if ($heredoc) { if ($id === T_END_HEREDOC) $heredoc = false; continue; }
            if ($t === '"' || $t === '`') { $quoted = !$quoted; if ($quoted) $this->tokens[] = [T_STRING, '__pw_unknown_string', 1]; continue; }
            if ($quoted) continue;
            if (in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG], true)) continue;
            if ($id === T_INLINE_HTML || $id === T_CLOSE_TAG) { $this->tokens[] = ';'; continue; }
            if ($id === T_OPEN_TAG_WITH_ECHO) $t = [T_ECHO, 'echo', $this->line($t)];
            $this->tokens[] = $t;
        }
        unset($raw);
        if ($quoted || $heredoc) throw new RuntimeException('unterminated PHP string');
        if (count($this->tokens) > 400000) throw new RuntimeException('PHP token budget');
        $i = 0; $vars = []; $this->walk($i, $vars, 0);
        $result = array_values($this->findings);
        $this->tokens = $this->handles = [];
        return $result;
    }
    private function group(&$i, $open = '(', $close = ')') {
        if (($this->tokens[$i] ?? null) !== $open) return [];
        ++$i; $n = 1; $out = [];
        while (isset($this->tokens[$i])) {
            $t = $this->tokens[$i++];
            if ($t === $open) ++$n;
            if ($t === $close && --$n === 0) return $out;
            $out[] = $t;
        }
        throw new RuntimeException('unbalanced PHP group');
    }
    private function body(&$i, &$vars, $context) {
        if (($this->tokens[$i] ?? null) === '{') { ++$i; $this->walk($i, $vars, $context, false, true); }
        else $this->walk($i, $vars, $context, true);
    }
    private function walk(&$i, &$vars, $context, $single = false, $braced = false) {
        if (++$this->depth > 128) throw new RuntimeException('PHP nesting budget');
        $buf = []; $level = 0; $overflow = false;
        while (isset($this->tokens[$i])) {
            $t = $this->tokens[$i]; $id = $this->id($t);
            if ($t === '}') {
                if (!$braced) throw new RuntimeException('unexpected PHP closing brace');
                ++$i; --$this->depth; return;
            }
            if ($id === T_FUNCTION || (($id === T_CLASS || $id === T_INTERFACE || $id === T_TRAIT) && $this->id($this->tokens[$i-1] ?? '') !== T_DOUBLE_COLON)) {
                // No facts or gates are borrowed from callers, sibling methods,
                // function parameters or closure captures. Those flows are unknown.
                if ($buf) $vars = []; // A closure can replace a previously tracked binding.
                $buf = []; ++$i;
                while (isset($this->tokens[$i]) && $this->tokens[$i] !== '{' && $this->tokens[$i] !== ';') ++$i;
                if (($this->tokens[$i] ?? null) === '{') { ++$i; $local = []; $this->walk($i, $local, 0, false, true); }
                continue;
            }
            if ($id === T_IF || $id === T_ELSEIF) {
                ++$i; $condition = $this->group($i); $branch = $vars;
                $this->restrictDispatch($condition, $branch);
                $this->body($i, $branch, $context | $this->gates($condition, $vars));
                // No branch joining or assumptions about which path executes.
                $vars = []; $buf = []; $level = 0; $overflow = false;
                if ($single) break;
                continue;
            }
            if ($id === T_ELSE) { ++$i; $branch = []; $this->body($i, $branch, $context); $vars = []; continue; }
            if ($t === '{') {
                // Unknown blocks/loops do not inherit speculative variable facts.
                ++$i; $local = []; $this->walk($i, $local, 0, false, true);
                $vars = []; $buf = []; $level = 0; $overflow = false; continue;
            }
            ++$i;
            if ($t === '(' || $t === '[') ++$level;
            if ($t === ')' || $t === ']') $level = max(0, $level - 1);
            if ($t === ';' && $level === 0) {
                $this->context = $context; if (!$overflow) $this->statement($buf, $vars); $buf = []; $overflow = false;
                if ($single) break;
            } else {
                if (!$overflow) $buf[] = $t;
                if (count($buf) > 8192) { $buf = []; $vars = []; $overflow = true; }
            }
        }
        if ($braced && !isset($this->tokens[$i])) throw new RuntimeException('unclosed PHP block');
        --$this->depth;
    }
    private function split($tokens, $separator) {
        $parts = []; $part = []; $depth = 0;
        foreach ($tokens as $t) {
            if ($depth === 0 && $this->text($t) === $separator) { $parts[] = $part; $part = []; continue; }
            if ($t === '(' || $t === '[') ++$depth;
            if ($t === ')' || $t === ']') --$depth;
            $part[] = $t;
        }
        $parts[] = $part; return $parts;
    }
    private function literal($t) {
        if ($this->id($t) !== T_CONSTANT_ENCAPSED_STRING) return null;
        $s = $t[1]; $q = $s[0]; $s = substr($s, 1, -1);
        return $q === "'" ? str_replace(["\\'", "\\\\"], ["'", "\\"], $s) : stripcslashes($s);
    }
    private function call($tokens) {
        if (count($tokens) < 3 || end($tokens) !== ')') return null;
        $name = strtolower($this->text($tokens[0])); $at = 1;
        if ($this->text($tokens[0]) === '\\') { $name = strtolower($this->text($tokens[1] ?? '')); $at = 2; }
        if (($tokens[$at] ?? null) !== '(') return null;
        // Methods/static methods and arbitrary namespace lookalikes are not APIs.
        $name = ltrim($name, '\\');
        if (strpos($name, '\\') !== false) return null;
        $inner = array_slice($tokens, $at + 1, -1);
        $depth = 0;
        foreach ($inner as $t) { if ($t === '(') ++$depth; if ($t === ')' && --$depth < 0) return null; }
        return [$name, $this->split($inner, ','), $this->line($tokens[0])];
    }
    private function fields($tokens, $vars) {
        if (($tokens[0] ?? null) === '[' && end($tokens) === ']') $tokens = array_slice($tokens, 1, -1);
        elseif (strtolower($this->text($tokens[0] ?? '')) === 'array' && ($tokens[1] ?? null) === '(' && end($tokens) === ')') $tokens = array_slice($tokens, 2, -1);
        else return [];
        $out = [];
        foreach ($this->split($tokens, ',') as $entry) {
            $pair = $this->split($entry, '=>');
            if (count($pair) !== 2 || count($pair[0]) !== 1) continue;
            $key = $this->literal($pair[0][0]);
            if ($key === null && $this->id($pair[0][0]) === T_STRING) $key = $this->text($pair[0][0]);
            if ($key !== null) $out[$key] = $this->value($pair[1], $vars);
        }
        return $out;
    }
    private function remote($f) { return is_string($f['literal']) && preg_match('~^https?://[^/\s]+~i', $f['literal']); }
    private function value($t, $vars, $depth = 0) {
        if (++$this->expressions > 32) { --$this->expressions; return $this->fact(); }
        try { return $this->expression($t,$vars,$depth); }
        finally { --$this->expressions; }
    }
    private function expression($t, $vars, $depth = 0) {
        if (!$t || $depth > 16 || count($t) > 2048) return $this->fact();
        if (count($t) === 1) {
            $v = $this->text($t[0]);
            if ($this->id($t[0]) === T_VARIABLE) return $vars[$v] ?? $this->fact();
            if ($this->id($t[0]) === T_CONSTANT_ENCAPSED_STRING) return $this->fact(0, $this->literal($t[0]));
            return $this->fact(0, in_array(strtolower($v), ['false', '0'], true) ? false : (strtolower($v) === 'true' || $v === '1' ? true : null));
        }
        if (count($t) === 4 && $t[1] === '[' && $t[3] === ']') {
            $base = $this->text($t[0]); $key = $this->literal($t[2]);
            if ($base === '$_SERVER' && $key === 'HTTP_USER_AGENT') return $this->fact(self::UA);
            if (in_array($base, ['$_POST','$_GET','$_REQUEST','$_COOKIE'], true)) {
                $bits = self::REQUEST;
                if ($base === '$_POST' && in_array($key, ['log','user_login','username'], true)) $bits |= self::LOGIN;
                if ($base === '$_POST' && in_array($key, ['pwd','user_pass','password'], true)) $bits |= self::PASSWORD;
                return $this->fact($bits);
            }
        }
        $parts = $this->split($t, '.');
        if (count($parts) > 1) {
            $bits = 0; $literal = '';
            foreach ($parts as $part) { $f = $this->value($part, $vars, $depth+1); $bits |= $f['bits']; $literal = is_string($literal) && is_string($f['literal']) ? $literal.$f['literal'] : null; }
            return $this->fact($bits, $literal);
        }
        $fields = $this->fields($t, $vars);
        if ($fields) { $bits = 0; foreach ($fields as $f) $bits |= $f['bits']; return $this->fact($bits); }
        $call = $this->call($t);
        if (!$call) return $this->fact();
        [$name,$args,$line] = $call;
        $a = $this->value($args[0] ?? [], $vars, $depth+1);
        if (isset($vars[$this->text($t[0])]) && ($vars[$this->text($t[0])]['bits'] & self::REQUEST)) $this->emit('PW-PHP-004',$line,'request-selected callable invoked in the same scope');
        if (in_array($name, ['call_user_func','call_user_func_array'], true) && ($a['bits'] & self::REQUEST)) $this->emit('PW-PHP-004',$line,'request-selected callable reaches '.$name);
        if ($name === 'base64_decode') return $this->fact($a['bits'] | (($a['bits'] & self::REMOTE) ? self::DECODED : 0), is_string($a['literal']) ? base64_decode($a['literal'],true) : null);
        if ($name === 'wp_remote_retrieve_body') return $a;
        if ($name === 'json_encode' || $name === 'http_build_query') return $this->fact($a['bits']);
        if ($name === 'curl_init' && $this->remote($a)) {
            if ($this->nextHandle >= 4096) throw new RuntimeException('PHP handle budget');
            $h = ++$this->nextHandle; $this->handles[$h] = ['url'=>true,'weak'=>false,'data'=>0,'return'=>false];
            return $this->fact(0,null,$h);
        }
        if (in_array($name, ['curl_setopt','curl_setopt_array'], true) && $a['handle'] !== null) {
            $h = $a['handle'];
            $options = $name === 'curl_setopt_array' ? $this->fields($args[1] ?? [], $vars) : [$this->text($args[1][0] ?? '')=>$this->value($args[2] ?? [],$vars,$depth+1)];
            if (!$options) $this->handles[$h] = ['url'=>false,'weak'=>false,'data'=>0,'return'=>false];
            foreach ($options as $key=>$v) {
                if ($key === 'CURLOPT_SSL_VERIFYPEER') $this->handles[$h]['weak'] = $v['literal'] === false;
                if ($key === 'CURLOPT_POSTFIELDS') $this->handles[$h]['data'] = $v['bits'];
                if ($key === 'CURLOPT_URL') $this->handles[$h]['url'] = (bool)$this->remote($v);
                if ($key === 'CURLOPT_RETURNTRANSFER') $this->handles[$h]['return'] = $v['literal'] === true;
            }
        }
        if ($name === 'curl_exec' && $a['handle'] !== null) {
            $h = $this->handles[$a['handle']];
            if ($h['url'] && $h['weak'] && ($h['data'] & 6) === 6) $this->emit('PW-PHP-005',$line,'POST username/password reach the same TLS-unverified cURL request');
            return $this->fact($h['url'] && $h['return'] ? self::REMOTE : 0);
        }
        if (in_array($name,['wp_remote_get','wp_remote_post','file_get_contents'],true) && $this->remote($a)) {
            $opt = $this->fields($args[1] ?? [], $vars);
            if (($opt['sslverify']['literal'] ?? null) === false && (($opt['body']['bits'] ?? 0) & 6) === 6) $this->emit('PW-PHP-005',$line,'POST username/password reach the same TLS-unverified HTTP request');
            return $this->fact(self::REMOTE);
        }
        if (in_array($name,['wp_add_inline_script','wp_enqueue_script'],true)) $this->browser($this->value($args[1] ?? [],$vars,$depth+1),$line,$name);
        return $this->fact();
    }
    private function browser($value, $line, $sink) {
        if (($this->context & 7) === 7 && ($value['bits'] & (self::REMOTE|self::DECODED)) === (self::REMOTE|self::DECODED)) {
            $this->emit('PW-PHP-006',$line,'admin/capability/Windows gate; remote response -> base64 decode -> '.$sink);
        }
    }
    private function statement($t, &$vars) {
        if (!$t) return;
        $first = $this->text($t[0]); $id = $this->id($t[0]);
        if ($id === T_RETURN || $id === T_THROW || $id === T_EXIT) { $this->value(array_slice($t,1),$vars); $vars = []; return; }
        if ($id === T_ECHO || $id === T_PRINT) {
            foreach ($this->split(array_slice($t,1),',') as $part) $this->browser($this->value($part,$vars),$this->line($t[0]),$first);
            return;
        }
        if ($id === T_VARIABLE && ($t[1] ?? null) === '=') {
            if (count($vars) >= 4096) throw new RuntimeException('PHP binding budget');
            $vars[$first] = $this->value(array_slice($t,2),$vars); return;
        }
        // Unsupported assignments, reference operations and unset invalidate
        // affected facts, rather than borrowing a stale source across a write.
        if ($id === T_UNSET || in_array('=', $t, true) || in_array('&', $t, true) || array_filter($t, function ($x) { return is_array($x) && in_array($x[0], [T_CONCAT_EQUAL, T_PLUS_EQUAL, T_MINUS_EQUAL, T_MUL_EQUAL, T_DIV_EQUAL, T_MOD_EQUAL, T_AND_EQUAL, T_OR_EQUAL, T_XOR_EQUAL, T_SL_EQUAL, T_SR_EQUAL, T_INC, T_DEC], true); })) {
            foreach ($t as $token) if ($this->id($token) === T_VARIABLE) unset($vars[$token[1]]);
            return;
        }
        $this->value($t,$vars);
    }
    private function restrictDispatch($tokens, &$vars) {
        $call = $this->call($tokens);
        if (!$call || $call[0] !== 'in_array') return;
        $args = $call[1]; $name = $this->text($args[0][0] ?? '');
        if (count($args[0] ?? []) !== 1 || !isset($vars[$name]) || $this->value($args[2] ?? [],$vars)['literal'] !== true) return;
        $allowed = $args[1] ?? [];
        if (($allowed[0] ?? '') !== '[' || end($allowed) !== ']') return;
        $entries = $this->split(array_slice($allowed,1,-1),',');
        if (!$entries) return;
        foreach ($entries as $entry) if (count($entry) !== 1 || $this->literal($entry[0]) === null) return;
        // A literal strict dispatch allowlist is not an arbitrary callable.
        // This does not assert that the allowlisted functions themselves are safe.
        $vars[$name] = $this->fact();
    }
    private function gates($tokens, $vars) {
        $mask = 0;
        // Only conjunctions of explicitly supported positive conditions count.
        if (count($this->split($tokens,'||')) > 1 || count($this->split($tokens,'or')) > 1) return 0;
        foreach ($this->split($tokens,'&&') as $part) {
            $call = $this->call($part);
            if ($call && $call[0] === 'is_admin' && empty($call[1][0])) $mask |= 1;
            if ($call && $call[0] === 'current_user_can' && $this->value($call[1][0] ?? [],$vars)['literal'] === 'manage_options') $mask |= 2;
            $cmp = $this->split($part,'!==');
            if (count($cmp) !== 2 || $this->value($cmp[1],$vars)['literal'] !== false) continue;
            $call = $this->call($cmp[0]);
            if (!$call || !in_array($call[0],['strpos','stripos'],true)) continue;
            $ua = $this->value($call[1][0] ?? [],$vars); $needle = $this->value($call[1][1] ?? [],$vars);
            if (($ua['bits'] & self::UA) && in_array($needle['literal'],['Windows','Win32','Win64'],true)) $mask |= 4;
        }
        return $mask;
    }
}
