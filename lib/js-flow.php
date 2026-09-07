<?php
/**
 * PressWarden conservative JavaScript flow recognizer (MIT).
 * Reads source as data; never executes JavaScript or fetches decoded URLs.
 * This is deliberately NOT a complete JavaScript parser or taint engine.
 */
final class PressWardenJsFlow
{
    private $frames = [];
    private $objects = [];
    private $findings = [];

    /** Streaming lexical tokens: kind, value, source line. */
    private static function tokens($source)
    {
        $length = strlen($source); $i = 0; $line = 1; $previous = '';
        while ($i < $length) {
            $c = $source[$i];
            if (ctype_space($c)) { if ($c === "\n") ++$line; ++$i; continue; }
            if (substr($source, $i, 2) === '//') {
                $end = strpos($source, "\n", $i + 2); $i = $end === false ? $length : $end; continue;
            }
            if (substr($source, $i, 2) === '/*') {
                $end = strpos($source, '*/', $i + 2);
                if ($end === false) throw new RuntimeException('unterminated JavaScript comment');
                $line += substr_count(substr($source, $i, $end + 2 - $i), "\n"); $i = $end + 2; continue;
            }
            $start = $i; $tokenLine = $line;
            if ($c === "'" || $c === '"' || $c === '`') {
                $quote = $c; ++$i; $raw = ''; $closed = false;
                while ($i < $length) {
                    $ch = $source[$i++];
                    if ($ch === $quote) { $closed = true; break; }
                    if ($quote === '`' && $ch === '$' && ($source[$i] ?? '') === '{') {
                        ++$i; self::skipInterpolation($source, $i, $line);
                        $raw .= '${OPAQUE}'; continue;
                    }
                    if ($ch === "\n") ++$line;
                    $raw .= $ch;
                    if ($ch === '\\' && $i < $length) {
                        $ch = $source[$i++]; $raw .= $ch; if ($ch === "\n") ++$line;
                    }
                }
                if (!$closed) throw new RuntimeException('unterminated JavaScript string');
                // Interpolated templates are opaque, not treated as literal code.
                $value = ($quote === '`' && strpos($raw, '${') !== false) ? null : self::stringValue($raw);
                yield [$value === null ? 'unknown' : 'string', $value, $tokenLine];
                $previous = 'literal'; continue;
            }
            // Ignore regex bodies rather than mistaking their examples for code.
            if ($c === '/' && ($previous === '' || in_array($previous, ['=', '(', '[', ',', ':', '!', '&&', '||', '?', 'return', '=>', ';', '{'], true))) {
                ++$i; $inClass = false; $closed = false;
                while ($i < $length && $source[$i] !== "\n") {
                    $ch = $source[$i++];
                    if ($ch === '\\' && $i < $length) { ++$i; continue; }
                    if ($ch === '[') $inClass = true;
                    if ($ch === ']') $inClass = false;
                    if ($ch === '/' && !$inClass) { $closed = true; break; }
                }
                if ($closed) {
                    while ($i < $length && ctype_alpha($source[$i])) ++$i;
                    yield ['unknown', '', $tokenLine]; $previous = 'literal'; continue;
                }
                $i = $start;
            }
            if (preg_match('~\G[A-Za-z_$][A-Za-z0-9_$]*~A', $source, $m, 0, $i)) {
                $i += strlen($m[0]); $previous = $m[0]; yield ['id', $m[0], $tokenLine]; continue;
            }
            if (preg_match('~\G(?:0[xX][0-9a-fA-F]+|[0-9]+)~A', $source, $m, 0, $i)) {
                $i += strlen($m[0]); $previous = 'literal'; yield ['number', $m[0], $tokenLine]; continue;
            }
            $operator = $c;
            foreach (['===', '!==', '=>', '==', '!=', '&&', '||', '+=', '-=', '++', '--', '?.', '<=', '>=', '??'] as $op) {
                if (substr($source, $i, strlen($op)) === $op) { $operator = $op; break; }
            }
            $i += strlen($operator); $previous = $operator; yield ['punct', $operator, $tokenLine];
        }
    }

    /** Consume template expressions as opaque data, including nested templates. */
    private static function skipInterpolation($s, &$i, &$line, $level = 0)
    {
        if ($level > 32) throw new RuntimeException('JavaScript template nesting limit reached');
        $depth = 1; $n = strlen($s);
        while ($i < $n) {
            $c = $s[$i++];
            if ($c === "\n") ++$line;
            if ($c === '{') ++$depth;
            elseif ($c === '}' && --$depth === 0) return;
            elseif ($c === "'" || $c === '"' || $c === '`') {
                $quote = $c; $closed = false;
                while ($i < $n) {
                    $c = $s[$i++];
                    if ($c === "\n") ++$line;
                    if ($c === '\\' && $i < $n) { if ($s[$i++] === "\n") ++$line; continue; }
                    if ($c === $quote) { $closed = true; break; }
                    if ($quote === '`' && $c === '$' && ($s[$i] ?? '') === '{') {
                        ++$i; self::skipInterpolation($s, $i, $line, $level + 1);
                    }
                }
                if (!$closed) throw new RuntimeException('unterminated JavaScript template expression');
            } elseif ($c === '/' && ($s[$i] ?? '') === '/') {
                $end = strpos($s, "\n", $i + 1); $i = $end === false ? $n : $end;
            } elseif ($c === '/' && ($s[$i] ?? '') === '*') {
                $end = strpos($s, '*/', $i + 1);
                if ($end === false) throw new RuntimeException('unterminated JavaScript template comment');
                $line += substr_count(substr($s, $i, $end + 2 - $i), "\n"); $i = $end + 2;
            }
        }
        throw new RuntimeException('unterminated JavaScript interpolation');
    }

    private static function utf8($cp)
    {
        if ($cp < 0 || $cp > 0x10ffff || ($cp >= 0xd800 && $cp <= 0xdfff)) return null;
        if ($cp < 0x80) return chr($cp);
        if ($cp < 0x800) return chr(0xc0 | ($cp >> 6)).chr(0x80 | ($cp & 63));
        if ($cp < 0x10000) return chr(0xe0 | ($cp >> 12)).chr(0x80 | (($cp >> 6) & 63)).chr(0x80 | ($cp & 63));
        return chr(0xf0 | ($cp >> 18)).chr(0x80 | (($cp >> 12) & 63)).chr(0x80 | (($cp >> 6) & 63)).chr(0x80 | ($cp & 63));
    }

    private static function stringValue($raw)
    {
        if (strlen($raw) > 16384) return null;
        $bad = false;
        $out = preg_replace_callback('~\\\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(\r\n|[\s\S]))~', function ($m) use (&$bad) {
            foreach ([1, 2, 3] as $n) if (!empty($m[$n])) {
                $value = self::utf8(hexdec($m[$n])); if ($value === null) $bad = true; return $value ?? '';
            }
            $escape = $m[4] ?? '';
            $map = ['n'=>"\n", 'r'=>"\r", 't'=>"\t", 'b'=>"\x08", 'f'=>"\x0c", 'v'=>"\x0b", '0'=>"\0", "\n"=>'', "\r\n"=>''];
            if ($escape === 'u' || $escape === 'x' || preg_match('~^[1-9]$~', $escape)) $bad = true;
            return $map[$escape] ?? $escape;
        }, $raw);
        return $bad ? null : $out;
    }

    private function lookup($name)
    {
        for ($i = count($this->frames) - 1; $i >= 0; --$i) {
            if (array_key_exists($name, $this->frames[$i]['vars'])) return $this->frames[$i]['vars'][$name];
            if (!$this->frames[$i]['inherit']) break;
        }
        return null;
    }

    private function bound($name)
    {
        for ($i = count($this->frames) - 1; $i >= 0; --$i) {
            if (array_key_exists($name, $this->frames[$i]['vars'])) return true;
            if (!$this->frames[$i]['inherit']) break;
        }
        return false;
    }

    private function assign($name, $value)
    {
        // A write invalidates outer facts; closed conditional blocks must not
        // leave a stale decoded URL available for a later unrelated sink.
        for ($i = count($this->frames) - 1; $i >= 0; --$i) {
            if (array_key_exists($name, $this->frames[$i]['vars'])) $this->frames[$i]['vars'][$name] = null;
            if (!$this->frames[$i]['inherit']) break;
        }
        $frame = count($this->frames) - 1;
        if (count($this->frames[$frame]['vars']) >= 4096) throw new RuntimeException('JavaScript binding limit reached');
        $this->frames[$frame]['vars'][$name] = $value;
    }

    private static function text($tokens)
    {
        $text = '';
        foreach ($tokens as $t) $text .= $t[0] === 'string' || $t[0] === 'unknown' ? ' LITERAL ' : $t[1];
        return $text;
    }

    private static function visitorCondition($tokens)
    {
        return (bool) preg_match('~(?:document\.(?:cookie|referrer)|navigator\.(?:userAgent|platform)|location\.(?:hostname|host)(?![A-Za-z])|(?:localStorage|sessionStorage)\.getItem|screen\.(?:width|height))~', self::text($tokens));
    }

    /** Recognize a small, bounded pure expression. Unknown code stays unknown. */
    private function expression($t, &$i, $depth = 0)
    {
        if ($depth > 12 || !isset($t[$i])) return null;
        $v = null; $token = $t[$i++];
        if ($token[0] === 'string') $v = ['type'=>'string', 'value'=>$token[1], 'encoded'=>false];
        elseif ($token[0] === 'number') $v = ['type'=>'number', 'value'=>intval($token[1], stripos($token[1], '0x') === 0 ? 16 : 10)];
        elseif ($token[1] === '(') {
            $v = $this->expression($t, $i, $depth + 1);
            if (($t[$i++][1] ?? '') !== ')') return null;
        } elseif ($token[0] === 'id') {
            $name = $token[1]; $root = $name;
            while (($t[$i][1] ?? '') === '.' && ($t[$i + 1][0] ?? '') === 'id') {
                $name .= '.'.$t[$i + 1][1]; $i += 2;
            }
            if (($t[$i][1] ?? '') !== '(') $v = $this->lookup($name);
            else {
                ++$i; $args = [];
                while (isset($t[$i]) && $t[$i][1] !== ')' && count($args) < 4096) {
                    $before = $i; $args[] = $this->expression($t, $i, $depth + 1);
                    if ($i <= $before) return null;
                    if (($t[$i][1] ?? '') !== ',') break;
                    ++$i;
                }
                if (($t[$i++][1] ?? '') !== ')' || $this->bound($root)) return null;
                if (in_array($name, ['document.createElement', 'window.document.createElement'], true) && ($args[0]['value'] ?? null) === 'script') {
                    if (count($this->objects) >= 4096) throw new RuntimeException('JavaScript object limit reached');
                    $id = count($this->objects); $this->objects[$id] = null; $v = ['type'=>'script', 'id'=>$id];
                } else $v = self::decode($name, $args);
            }
        }
        while (($t[$i][1] ?? '') === '+') {
            ++$i; $right = $this->expression($t, $i, $depth + 1);
            if (($v['type'] ?? '') !== 'string' || ($right['type'] ?? '') !== 'string') return null;
            $v['value'] .= $right['value']; $v['encoded'] = $v['encoded'] || $right['encoded'];
            if (strlen($v['value']) > 16384) return null;
        }
        return $v;
    }

    private static function decode($name, $args)
    {
        $name = preg_replace('~^window\.~', '', $name);
        $value = null;
        if ($name === 'String.fromCharCode') {
            $value = ''; $units = [];
            foreach ($args as $a) {
                if (($a['type'] ?? '') !== 'number' || $a['value'] < 0 || $a['value'] > 65535) return null;
                $units[] = $a['value'];
            }
            for ($i = 0; $i < count($units); ++$i) {
                $cp = $units[$i];
                if ($cp >= 0xd800 && $cp <= 0xdbff && isset($units[$i + 1]) && $units[$i + 1] >= 0xdc00 && $units[$i + 1] <= 0xdfff) {
                    $cp = 0x10000 + (($cp - 0xd800) << 10) + ($units[++$i] - 0xdc00);
                }
                $char = self::utf8($cp); if ($char === null) return null; $value .= $char;
            }
        } elseif (count($args) === 1 && ($args[0]['type'] ?? '') === 'string') {
            $raw = $args[0]['value'];
            if ($name === 'atob') {
                $raw = preg_replace('~[\t\n\f\r ]~', '', $raw);
                if (!preg_match('~^[A-Za-z0-9+/]*={0,2}$~D', $raw) || strlen($raw) % 4 === 1) return null;
                $value = base64_decode($raw, true); if ($value === false) return null;
            } elseif ($name === 'decodeURIComponent') {
                if (preg_match('~%(?![0-9a-fA-F]{2})~', $raw)) return null;
                $value = rawurldecode($raw); if (!preg_match('//u', $value)) return null;
            } elseif ($name === 'unescape') {
                $value = preg_replace_callback('~%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})~', function ($m) {
                    return self::utf8(hexdec($m[1] !== '' ? $m[1] : $m[2])) ?? '';
                }, $raw);
            }
            // URL normalization of an already-readable URL is not obfuscation.
            if ($value === $raw && !($args[0]['encoded'] ?? false)) return null;
        }
        return $value === null ? null : ['type'=>'string', 'value'=>$value, 'encoded'=>true];
    }

    private function recordTarget($value, $rule, $sink, $line, $gated)
    {
        if (($value['type'] ?? '') !== 'string' || empty($value['encoded'])) return;
        $url = trim($value['value']);
        $mime = $rule === 'PW-JS-004' ? 'text/html|(?:text|application)/(?:javascript|ecmascript)' : '(?:text|application)/(?:javascript|ecmascript)';
        $executable = preg_match('~^(?:javascript:|data:(?:'.$mime.')(?:[;,]|$))~i', $url);
        $host = null;
        if (preg_match('~^(?:https?:)?//~i', $url) && !preg_match('~[\x00-\x20\x7f]~', $url)) {
            $host = parse_url(strpos($url, '//') === 0 ? 'https:'.$url : $url, PHP_URL_HOST);
        }
        if (!$executable && (!is_string($host) || $host === '' || !$gated)) return;
        // Visitor targeting + encoding is suspicious, not proof of a campaign.
        // IP hosts are not intrinsically malicious and receive no severity boost.
        $this->findings[$rule] = [
            'rule'=>$rule, 'kind'=>$executable ? 'ALERT' : 'REVIEW', 'line'=>$line,
            'evidence'=>'literal decode -> '.$sink.($gated ? '; enclosing visitor condition' : '').'; target='.($executable ? 'executable URI' : preg_replace('~[^A-Za-z0-9.\[\]:_-]~', '?', substr($host, 0, 253)))
        ];
    }

    private function statement($t, $gated)
    {
        if (!$t) return;
        // Single-statement if bodies get only their actual controlling condition.
        if (($t[0][1] ?? '') === 'if' && ($t[1][1] ?? '') === '(') {
            $depth = 1; $i = 2;
            for (; isset($t[$i]); ++$i) {
                if ($t[$i][1] === '(') ++$depth;
                if ($t[$i][1] === ')' && --$depth === 0) break;
            }
            if ($depth === 0) {
                $this->statement(array_slice($t, $i + 1), $gated || self::visitorCondition(array_slice($t, 2, $i - 2))); return;
            }
        }
        for ($i = 0, $n = count($t); $i < $n; ++$i) {
            if ($t[$i][0] !== 'id') continue;
            $start = $i; $name = $t[$i][1]; $root = $name; $j = $i + 1;
            if ($i > 0 && in_array($t[$i - 1][1], ['.', '?.'], true)) continue;
            while (($t[$j][1] ?? '') === '.' && ($t[$j + 1][0] ?? '') === 'id') { $name .= '.'.$t[$j + 1][1]; $j += 2; }
            $operator = $t[$j][1] ?? '';
            if (in_array($operator, ['=', '+=', '-=', '++', '--'], true)) {
                $k = $j + 1; $value = $operator === '=' ? $this->expression($t, $k) : null;
                if ($k < $n && !in_array($t[$k][1], [',', ')'], true)) $value = null;
                if (in_array($name, ['location', 'location.href', 'window.location', 'window.location.href'], true) && !$this->bound($root) && !in_array($t[$i - 1][1] ?? '', ['var', 'let', 'const'], true)) {
                    $this->recordTarget($value, 'PW-JS-004', $name, $t[$i][2], $gated);
                } elseif (substr($name, -4) === '.src') {
                    $object = $this->lookup(substr($name, 0, -4));
                    if (($object['type'] ?? '') === 'script') $this->objects[$object['id']] = $value;
                } elseif (strpos($name, '.') === false) $this->assign($name, $value);
                continue;
            }
            if ($operator !== '(') continue;
            $k = $j + 1; $arg = $this->expression($t, $k);
            if (!in_array($t[$k][1] ?? '', [')', ','], true)) continue;
            if (in_array($name, ['location.assign', 'location.replace', 'window.location.assign', 'window.location.replace'], true) && !$this->bound($root)) {
                $this->recordTarget($arg, 'PW-JS-004', $name, $t[$i][2], $gated);
            } elseif (preg_match('~\.(?:appendChild|insertBefore|append|prepend)$~', $name) && ($arg['type'] ?? '') === 'script') {
                $this->recordTarget($this->objects[$arg['id']] ?? null, 'PW-JS-002', 'script.src -> DOM insertion', $t[$i][2], $gated);
            } elseif (substr($name, -13) === '.setAttribute' && ($arg['value'] ?? '') === 'src' && ($t[$k][1] ?? '') === ',') {
                ++$k; $value = $this->expression($t, $k); $object = $this->lookup(substr($name, 0, -13));
                if (($t[$k][1] ?? '') === ')' && ($object['type'] ?? '') === 'script') $this->objects[$object['id']] = $value;
            } elseif (in_array($name, ['eval', 'Function', 'window.eval', 'window.Function'], true) && !$this->bound($root) && ($arg['type'] ?? '') === 'string' && !empty($arg['encoded'])) {
                $code = ''; $count = 0;
                foreach (self::tokens($arg['value']) as $token) {
                    if (++$count > 2048) break;
                    $code .= $token[0] === 'string' || $token[0] === 'unknown' ? ' LITERAL ' : $token[1];
                }
                if (preg_match('~(?:\bfetch\(|\bXMLHttpRequest\b|\blocation(?:\.href)?=|\blocation\.(?:replace|assign)\(|\bdocument\.(?:write|createElement)\()~', $code)) {
                    $this->findings['PW-JS-001'] = ['rule'=>'PW-JS-001', 'kind'=>'ALERT', 'line'=>$t[$start][2], 'evidence'=>'literal decoded code -> '.$name.'; decoded browser/network operation'];
                }
            }
        }
    }

    public function scan($source)
    {
        $this->frames = [['vars'=>[], 'inherit'=>false, 'gate'=>false]];
        $this->objects = []; $this->findings = []; $statement = [];
        foreach (self::tokens($source) as $token) {
            $symbol = $token[0] === 'punct' ? $token[1] : '';
            $f = count($this->frames) - 1;
            if ($symbol === '{') {
                $header = self::text($statement);
                $control = preg_match('~^(?:if|else|for|while|switch|try|catch|finally)\b~', $header) && strpos($header, '=>') === false && strpos($header, 'function') === false;
                $gate = $control && ($this->frames[$f]['gate'] || (strpos($header, 'if(') === 0 && self::visitorCondition($statement)));
                if (count($this->frames) >= 256) throw new RuntimeException('JavaScript nesting limit reached');
                $locals = [];
                if (!$control) {
                    // Function parameters and assigned object/function names can
                    // shadow browser globals. Never assume a local `location`
                    // or `atob` is the built-in API.
                    foreach ($statement as $index => $part) {
                        if ($part[0] !== 'id') continue;
                        if (in_array($statement[$index - 1][1] ?? '', ['function', 'var', 'let', 'const'], true)) $this->assign($part[1], null);
                        if (in_array($part[1], ['window', 'document', 'location', 'atob', 'String', 'eval', 'Function', 'decodeURIComponent', 'unescape'], true)) $locals[$part[1]] = null;
                    }
                }
                $this->frames[] = ['vars'=>$locals, 'inherit'=>(bool)$control, 'gate'=>(bool)$gate]; $statement = [];
            } elseif ($symbol === '}') {
                $this->statement($statement, $this->frames[$f]['gate']); $statement = [];
                if (count($this->frames) > 1) array_pop($this->frames);
            } elseif ($symbol === ';') {
                $this->statement($statement, $this->frames[$f]['gate']); $statement = [];
            } else {
                $statement[] = $token;
                // Large application expressions are outside this recognizer;
                // keep processing following blocks instead of a giant regex.
                if (count($statement) > 8192) $statement = [['unknown', '', $token[2]]];
            }
        }
        $this->statement($statement, $this->frames[count($this->frames) - 1]['gate']);
        return array_values($this->findings);
    }
}
