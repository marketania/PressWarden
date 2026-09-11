<?php
/** Verified, bounded quarantine. Scanned content is data, never executable code.
 * All path operations require trusted filesystem ancestors and the executing account.
 * Identity/hash rechecks reduce races; PHP does not provide race-free openat/unlinkat.
 */
class PressWardenQuarantineError extends RuntimeException {}

class PressWardenQuarantine {
    const MAX_ENTRIES = 10000;
    const MAX_BYTES = 268435456;
    const MAX_MANIFEST = 8388608;
    private $count = 0;
    private $bytes = 0;
    private $parentItem = null;
    private $parentIndex = [];

    private function fail($reason) { throw new PressWardenQuarantineError($reason); }
    private function statPath($path) {
        clearstatcache(true, $path);
        $s = @lstat($path);
        if ($s === false) $this->fail('unreadable or missing path');
        return array_intersect_key($s, array_flip(['dev','ino','mode','nlink','uid','gid','size','mtime','ctime']));
    }
    private function inside($path, $parent) { return $path === $parent || strpos($path, $parent.'/') === 0; }
    private function absolute($path) {
        if (!is_string($path) || $path === '' || $path[0] !== '/' || strlen($path) > 4096
            || preg_match('~[\x00-\x1f\x7f]|//|/(?:\.|\.\.)(?:/|$)~', $path)) $this->fail('unsafe path');
        return rtrim($path, '/') ?: '/';
    }
    public function plainParents($path, $includeSelf = false) {
        $this->absolute($path);
        $p = $includeSelf ? $path : dirname($path);
        while ($p !== '/') {
            $s = $this->statPath($p);
            if (($s['mode'] & 0170000) !== 0040000) $this->fail('symlink or non-directory ancestor');
            $p = dirname($p);
        }
    }
    private function wordpress($p) {
        return is_file($p.'/wp-load.php') && is_file($p.'/wp-settings.php')
            && is_file($p.'/wp-includes/version.php') && is_dir($p.'/wp-admin') && is_dir($p.'/wp-content');
    }
    private function checkPolicy($policy) {
        foreach (['root','quarantine'] as $k) {
            if (!isset($policy[$k]) || $this->absolute($policy[$k]) !== $policy[$k]) $this->fail('invalid scope');
        }
        if ($policy['root'] === '/' || !in_array($policy['mode'] ?? '', ['generic','cleanup'], true)) $this->fail('invalid scope');
        $this->plainParents($policy['root'], true);
        foreach (['sites','blocked'] as $k) {
            if (!isset($policy[$k]) || !is_array($policy[$k]) || count($policy[$k]) > self::MAX_ENTRIES) $this->fail('invalid scope');
            foreach ($policy[$k] as $p) $this->absolute($p);
        }
        if (!$policy['sites']) $this->fail('no validated site scope');
    }
    private function allowed($path, $policy, $top = true) {
        $path = $this->absolute($path);
        if (!$this->inside($path, $policy['root']) || $path === $policy['root']) $this->fail('out-of-scope target');
        $this->plainParents($path);
        foreach ($policy['blocked'] as $p) {
            clearstatcache(true, $p);
            $resolved = @realpath($p);
            foreach ([$p, $resolved] as $blocked) {
                if ($blocked !== false && ($this->inside($path, $blocked) || $this->inside($blocked, $path))) $this->fail('protected or excluded target');
            }
        }
        if ($this->inside($path, $policy['quarantine']) || $this->inside($policy['quarantine'], $path)) $this->fail('quarantine overlaps target');
        $site = '';
        foreach ($policy['sites'] as $s) {
            if ($this->inside($s, $policy['root']) && $this->inside($path, $s) && strlen($s) > strlen($site)) $site = $s;
            if ($path === $s || $this->inside($s, $path)) $this->fail('target contains a WordPress root');
        }
        if ($site === '' || !$this->wordpress($site)) $this->fail('site no longer validates');
        // Also protect nested installations even if a discovery snapshot omitted one.
        for ($p = dirname($path); $p !== $site && $this->inside($p, $site); $p = dirname($p)) {
            if ($this->wordpress($p)) $site = $p;
        }
        $rel = substr($path, strlen($site) + 1);
        if (preg_match('~^(?:wp-admin|wp-includes)(?:/|$)|^(?:wp-config\.php|\.htaccess|\.user\.ini|php\.ini|index\.php|wp-load\.php|wp-blog-header\.php|wp-settings\.php|wp-cron\.php|wp-login\.php|wp-mail\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php|wp-comments-post\.php|xmlrpc\.php)$|^wp-content/themes/[^/]+/functions\.php$~D', $rel)) $this->fail('protected WordPress file');
        $s = $this->statPath($path); $type = $s['mode'] & 0170000;
        if ($type === 0040000) {
            if ($this->wordpress($path)) $this->fail('target contains a WordPress root');
            if ($top) {
                $allowed = ['.git','.svn','.hg'];
                if ($policy['mode'] === 'cleanup') $allowed = array_merge($allowed, ['__MACOSX','.AppleDouble','.idea','.vscode','.pytest_cache','.mypy_cache','.sass-cache']);
                if (!in_array(basename($path), $allowed, true)) $this->fail('directory requires manual handling');
                if (!in_array(basename($path), ['.git','.svn','.hg','__MACOSX','.AppleDouble'], true)
                    && preg_match('~^wp-content/(?:plugins|themes)/~', $rel)) $this->fail('packaged development directory');
            }
        } elseif ($type !== 0100000 && $type !== 0120000) $this->fail('special file requires manual handling');
        if ($type === 0100000 && $s['nlink'] !== 1) $this->fail('hard-linked file requires manual handling');
        if ($top && $policy['mode'] === 'cleanup') {
            $base = basename($path);
            $os = in_array($base, ['__MACOSX','.AppleDouble','.DS_Store','Thumbs.db','desktop.ini','.LSOverride'], true) || strpos($base, '._') === 0;
            if (!$os) {
                $development = ['.idea','.vscode','.pytest_cache','.mypy_cache','.sass-cache','.gitignore','.gitattributes','.gitkeep',
                    '.editorconfig','.eslintignore','.stylelintignore','.prettierignore','.npmignore','phpcs.xml','phpcs.xml.dist',
                    '.phpcs.xml','.phpcs.xml.dist','phpstan.neon','phpstan.neon.dist','phpunit.xml','phpunit.xml.dist',
                    '.eslintcache','.stylelintcache','.phpunit.result.cache'];
                if (!in_array($base, $development, true)) $this->fail('not a disposable metadata target');
                if (preg_match('~^wp-content/(?:plugins|themes)/~', $rel)) $this->fail('packaged development metadata');
                for ($d = dirname($path); $this->inside($d, $policy['root']); $d = dirname($d)) {
                    if (file_exists($d.'/.git') || is_link($d.'/.git')) $this->fail('development metadata in a live Git tree');
                    if ($d === $policy['root']) break;
                }
            }
        }
        return $s;
    }
    private function directoryIdentity($path) {
        $s = $this->statPath($path);
        if (($s['mode'] & 0170000) !== 0040000) $this->fail('directory identity changed');
        return array_intersect_key($s, array_flip(['dev','ino','mode','uid','gid']));
    }
    private function parentIdentities($path, $root) {
        $parents = [];
        for ($p = dirname($path); $this->inside($p, $root); $p = dirname($p)) {
            $parents[$p] = $this->directoryIdentity($p);
            if ($p === $root) break;
        }
        return $parents;
    }
    private function assertParents($item, $path) {
        $this->plainParents($path);
        // Build once per selected tree, not once per leaf (avoid quadratic work).
        if ($this->parentItem !== $item['original']) {
            $this->parentItem = $item['original']; $this->parentIndex = $item['parents'];
            foreach ($item['entries'] as $e) {
                if ($e['type'] !== 'directory') continue;
                $p = $this->sourcePath($item, $e);
                $this->parentIndex[$p] = array_intersect_key($e['identity'], array_flip(['dev','ino','mode','uid','gid']));
            }
        }
        for ($p = dirname($path); isset($this->parentIndex[$p]); $p = dirname($p)) {
            if ($this->directoryIdentity($p) !== $this->parentIndex[$p]) $this->fail('source ancestor changed');
        }
    }
    private function privateDirectory($path) {
        $path = $this->absolute($path);
        if (!file_exists($path) && !is_link($path)) {
            $this->privateDirectory(dirname($path));
            if (!@mkdir($path, 0700)) $this->fail('cannot create private directory');
        }
        $this->plainParents($path, true);
    }
    private function hashFile($path, $expected) {
        $this->plainParents($path);
        if ($this->statPath($path) !== $expected) $this->fail('source changed');
        $h = @fopen($path, 'rb');
        if ($h === false) $this->fail('cannot read file');
        try {
            $fs = @fstat($h);
            if (!$fs || $fs['ino'] !== $expected['ino'] || $fs['dev'] !== $expected['dev'] || ($fs['mode'] & 0170000) !== 0100000) $this->fail('source changed');
            $hash = hash_init('sha256'); $size = 0;
            while (!feof($h)) {
                $chunk = fread($h, 65536);
                if ($chunk === false || ($chunk === '' && !feof($h))) $this->fail('file read failed');
                $size += strlen($chunk);
                if ($size > self::MAX_BYTES || $size > $expected['size']) $this->fail('source grew or exceeded limit');
                hash_update($hash, $chunk);
            }
            if ($size !== $expected['size'] || $this->statPath($path) !== $expected) $this->fail('source changed');
            return hash_final($hash);
        } finally { fclose($h); }
    }
    private function walk($path, $relative, $policy, &$entries, $device, $depth = 0) {
        if (++$this->count > self::MAX_ENTRIES || $depth > 64) $this->fail('entry or depth limit');
        $s = $this->allowed($path, $policy, $relative === '');
        if ($s['dev'] !== $device) $this->fail('filesystem boundary');
        $type = $s['mode'] & 0170000;
        $e = ['path64'=>base64_encode($relative), 'identity'=>$s, 'type'=>$type === 0040000 ? 'directory' : ($type === 0120000 ? 'link' : 'file')];
        if ($type !== 0040000) {
            $this->bytes += $s['size'];
            if ($s['size'] < 0 || $this->bytes > self::MAX_BYTES) $this->fail('quarantine byte limit');
            if ($type === 0120000) {
                $target = @readlink($path);
                if ($target === false || strlen($target) !== $s['size'] || $this->statPath($path) !== $s) $this->fail('link changed');
                $e['sha256'] = hash('sha256', $target);
            } else $e['sha256'] = $this->hashFile($path, $s);
            $e['bytes'] = $s['size'];
        }
        $entries[] = $e;
        if ($type === 0040000) {
            $h = @opendir($path);
            if ($h === false) $this->fail('directory read failed');
            $names = [];
            try {
                while (false !== ($n = readdir($h))) {
                    if ($n === '.' || $n === '..') continue;
                    if (count($names) + $this->count >= self::MAX_ENTRIES) $this->fail('entry limit');
                    $names[] = $n;
                }
            } finally { closedir($h); }
            sort($names, SORT_STRING);
            foreach ($names as $n) $this->walk($path.'/'.$n, $relative === '' ? $n : $relative.'/'.$n, $policy, $entries, $device, $depth + 1);
            if ($this->statPath($path) !== $s) $this->fail('directory changed');
        }
    }
    private function snapshot($path, $policy) {
        $entries = []; $s = $this->allowed($path, $policy);
        $this->walk($path, '', $policy, $entries, $s['dev']);
        return $entries;
    }
    public function plan($policy, $targets) {
        $this->checkPolicy($policy); $this->count = 0; $this->bytes = 0;
        if (!is_array($targets) || !$targets || count($targets) > 1000) $this->fail('invalid target count');
        $targets = array_values(array_unique($targets)); sort($targets, SORT_STRING); $items = [];
        foreach ($targets as $p) {
            $overlap = false;
            foreach ($items as $item) if ($this->inside($p, $item['original'])) $overlap = true;
            if (!$overlap) $items[] = ['original'=>$p, 'parents'=>$this->parentIdentities($p, $policy['root']), 'entries'=>$this->snapshot($p, $policy)];
        }
        return ['format'=>1, 'policy'=>$policy, 'created'=>gmdate('c'), 'items'=>$items];
    }
    public function writeJson($path, $value) {
        $data = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($data === false || strlen($data) > self::MAX_MANIFEST) $this->fail('manifest encoding or size limit');
        $this->writeNew($path, $data."\n");
    }
    protected function writeNew($path, $bytes) {
        $this->plainParents($path); $mask = umask(0077);
        try { $h = @fopen($path, 'xb'); } finally { umask($mask); }
        if ($h === false) $this->fail('cannot create evidence record');
        try { $this->writeAll($h, $bytes); } finally { if (!fclose($h)) $this->fail('record close failed'); }
    }
    private function writeAll($h, $data) {
        for ($p = 0, $n = strlen($data); $p < $n; $p += $w) {
            $w = @fwrite($h, substr($data, $p));
            if ($w === false || $w === 0) $this->fail('evidence write failed');
        }
        if (!@fflush($h)) $this->fail('evidence flush failed');
    }
    public function readJson($path) {
        $this->plainParents($path); $s = $this->statPath($path);
        if (($s['mode'] & 0170000) !== 0100000 || $s['nlink'] !== 1 || $s['size'] > self::MAX_MANIFEST) $this->fail('unsafe manifest');
        $raw = @file_get_contents($path, false, null, 0, self::MAX_MANIFEST + 1);
        $v = $raw === false ? null : json_decode($raw, true, 128);
        if (strlen((string)$raw) > self::MAX_MANIFEST || !is_array($v)) $this->fail('invalid manifest');
        return $v;
    }
    protected function copyObject($original, $dest, $e) {
        if ($e['type'] === 'link') {
            $target = @readlink($original);
            if ($target === false) $this->fail('cannot read link');
            $this->writeNew($dest, $target); return;
        }
        $this->plainParents($original); $s = $this->statPath($original);
        if ($s !== $e['identity']) $this->fail('source changed before copy');
        $in = @fopen($original, 'rb');
        if ($in === false) $this->fail('cannot read source');
        $mask = umask(0077);
        try { $out = @fopen($dest, 'xb'); } finally { umask($mask); }
        if ($out === false) { fclose($in); $this->fail('cannot create evidence copy'); }
        try {
            $s2 = fstat($in);
            if ($s2['ino'] !== $s['ino'] || $s2['dev'] !== $s['dev'] || ($s2['mode'] & 0170000) !== 0100000) $this->fail('source changed before copy');
            $copied = stream_copy_to_stream($in, $out, $e['bytes'] + 1);
            if ($copied !== $e['bytes'] || !fflush($out)) $this->fail('copy incomplete or source changed');
        } finally { fclose($in); if (!fclose($out)) $this->fail('copy close failed'); }
    }
    private function sourcePath($item, $e) {
        $rel = base64_decode($e['path64'], true);
        if ($rel === false || ($rel !== '' && (strpos($rel, "\0") !== false || preg_match('~^/|//|(?:^|/)\.{1,2}(?:/|$)~', $rel)))) $this->fail('invalid entry path');
        return $item['original'].($rel === '' ? '' : '/'.$rel);
    }
    protected function emit($record) { $this->writeAll(STDOUT, $record); }
    // This method is the test seam for deterministic filesystem/write failures.
    protected function removeEntry($path, $directory) { return $directory ? @rmdir($path) : @unlink($path); }
    protected function event($case, $index, $event, $path = '') {
        $this->writeJson($case.'/event-'.sprintf('%05d', $index).'-'.$event.'.json', ['event'=>$event, 'original_path64'=>base64_encode($path), 'time'=>gmdate('c')]);
    }
    public function apply($plan) {
        if (($plan['format'] ?? null) !== 1 || !is_array($plan['items'] ?? null)) $this->fail('invalid plan');
        $policy = $plan['policy']; $this->checkPolicy($policy);
        $this->parentItem = null; $this->parentIndex = [];
        $targets = array_column($plan['items'], 'original');
        // Never trust a saved plan as current state. Whole-selection precheck.
        // The snapshot intentionally predates interactive approval so approval remains
        // bound to the exact bytes that produced the finding. If a target changes or
        // disappears while the operator is deciding, refuse the entire batch rather
        // than deleting content that was not part of the approved snapshot.
        try {
            $current = $this->plan($policy, $targets);
        } catch (PressWardenQuarantineError $e) {
            $this->fail('approved selection revalidation failed: '.$e->getMessage());
        }
        if ($current['items'] !== $plan['items']) $this->fail('approved selection changed since snapshot');
        $q = $policy['quarantine'];
        foreach ($policy['sites'] as $s) if ($this->inside($q, $s)) $this->fail('quarantine must be outside WordPress sites');
        for ($p = $q; $p !== '/'; $p = dirname($p)) {
            if ($this->wordpress($p)) $this->fail('quarantine must be outside WordPress sites');
        }
        $this->privateDirectory($q);
        $id = 'case-'.gmdate('Ymd\THis\Z').'-'.bin2hex(random_bytes(8)); $case = $q.'/'.$id;
        if (!@mkdir($case, 0700)) $this->fail('cannot reserve quarantine case');
        $removed = 0; $seq = 0;
        try {
            $manifest = ['format'=>1, 'tool'=>'PressWarden', 'case_id'=>$id, 'created'=>gmdate('c'),
                'presswarden_version'=>$policy['version'] ?? 'unknown', 'check'=>$policy['check'] ?? '', 'section'=>$policy['section'] ?? '', 'run_id'=>$policy['run_id'] ?? '', 'items'=>$plan['items']];
            foreach ($manifest['items'] as &$item) foreach ($item['entries'] as &$e) {
                if ($e['type'] !== 'directory') $e['object'] = sprintf('%05d.bin', ++$seq);
            }
            unset($item, $e);
            $this->writeJson($case.'/manifest.json', $manifest);
            if (!@mkdir($case.'/objects', 0700)) $this->fail('cannot create object store');
            foreach ($manifest['items'] as $item) foreach ($item['entries'] as $e) {
                if ($e['type'] !== 'directory') {
                    $original = $this->sourcePath($item, $e); $this->assertParents($item, $original);
                    $this->copyObject($original, $case.'/objects/'.$e['object'], $e);
                }
            }
            $this->verifyObjects($case, $manifest);
            if ($this->plan($policy, $targets)['items'] !== $plan['items']) $this->fail('source changed during capture');
            $this->writeJson($case.'/verified.json', ['manifest_sha256'=>hash_file('sha256', $case.'/manifest.json'), 'time'=>gmdate('c')]);
            $seq = 0;
            foreach ($manifest['items'] as $item) {
                foreach (array_reverse($item['entries']) as $e) {
                    $path = $this->sourcePath($item, $e); $this->assertParents($item, $path); $s = $this->allowed($path, $policy, $e['path64'] === '');
                    if ($e['type'] === 'directory') {
                        foreach (['dev','ino','mode','uid','gid'] as $k) if ($s[$k] !== $e['identity'][$k]) $this->fail('directory identity changed');
                    } else {
                        if ($s !== $e['identity']) $this->fail('source identity changed');
                        $hash = $e['type'] === 'link' ? hash('sha256', (string)@readlink($path)) : $this->hashFile($path, $s);
                        if (!hash_equals($e['sha256'], $hash)) $this->fail('source content changed');
                        // Recheck the retained copy immediately before removal too.
                        $this->verifyObject($case.'/objects/'.$e['object'], $e);
                    }
                    $this->event($case, ++$seq, 'remove-started', $path);
                    $this->assertParents($item, $path);
                    $now = $this->statPath($path);
                    if ($now !== $s) $this->fail('source changed before removal');
                    if (!$this->removeEntry($path, $e['type'] === 'directory')) $this->fail('removal failed; retained copies are available');
                    $this->event($case, $seq, 'removed', $path);
                }
                ++$removed;
                $this->emit("REMOVED\t".$id."\t".base64_encode($item['original'])."\n");
            }
            $this->writeJson($case.'/complete.json', ['removed_targets'=>$removed, 'entries'=>$seq, 'time'=>gmdate('c')]);
            $this->emit("COMPLETE\t".$id."\t".$removed."\n");
            return $id;
        } catch (Throwable $e) {
            // Do not remove a partial case, restore code into a live site, or hide partial removal.
            try { $this->writeJson($case.'/incomplete.json', ['state'=>'incomplete', 'removed_targets'=>$removed, 'time'=>gmdate('c')]); } catch (Throwable $ignored) {}
            fwrite(STDERR, "INCOMPLETE: quarantine action stopped; case $id retained. Some approved entries may already have been removed.\n");
            throw $e;
        }
    }
    private function verifyObject($p, $e) {
        if (!isset($e['sha256'], $e['bytes']) || !is_int($e['bytes']) || $e['bytes'] < 0 || $e['bytes'] > self::MAX_BYTES
            || !is_string($e['sha256']) || !preg_match('/^[a-f0-9]{64}$/D', $e['sha256'])) $this->fail('invalid object metadata');
        $s = $this->statPath($p);
        if (($s['mode'] & 0170000) !== 0100000 || $s['nlink'] !== 1 || $s['size'] !== $e['bytes']) $this->fail('unsafe or incomplete evidence copy');
        if (!hash_equals($e['sha256'], $this->hashFile($p, $s))) $this->fail('evidence hash mismatch');
    }
    private function verifyObjects($case, $manifest) {
        $this->plainParents($case.'/objects', true);
        if (($manifest['format'] ?? null) !== 1 || ($manifest['tool'] ?? '') !== 'PressWarden'
            || !is_array($manifest['items'] ?? null) || !$manifest['items']) $this->fail('invalid case manifest');
        $n = 0; $bytes = 0; $seen = [];
        foreach ($manifest['items'] as $item) {
            if (!is_array($item['entries'] ?? null) || !$item['entries']) $this->fail('invalid case entries');
            foreach ($item['entries'] as $e) {
                if (++$n > self::MAX_ENTRIES || !in_array($e['type'] ?? '', ['file','link','directory'], true)) $this->fail('invalid entry or limit');
                if ($e['type'] === 'directory') continue;
                if (!is_string($e['object'] ?? null) || !preg_match('/^[0-9]{5}\.bin$/D', $e['object']) || isset($seen[$e['object']])) $this->fail('invalid object path');
                $seen[$e['object']] = true;
                $this->verifyObject($case.'/objects/'.$e['object'], $e);
                $bytes += $e['bytes']; if ($bytes > self::MAX_BYTES) $this->fail('evidence byte limit');
            }
        }
        $h = @opendir($case.'/objects'); if (!$h) $this->fail('cannot read objects');
        try { while (false !== ($name = readdir($h))) if ($name !== '.' && $name !== '..' && !isset($seen[$name])) $this->fail('unexpected evidence object'); }
        finally { closedir($h); }
        return count($seen);
    }
    public function verify($root, $id) {
        $root = $this->absolute($root);
        if (!is_string($id) || !preg_match('/^case-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}$/D', $id)) $this->fail('invalid case ID');
        $case = $root.'/'.$id; $this->plainParents($case, true);
        $m = $this->readJson($case.'/manifest.json');
        if (($m['case_id'] ?? '') !== $id) $this->fail('case ID mismatch');
        $n = $this->verifyObjects($case, $m);
        $v = $this->readJson($case.'/verified.json');
        if (($v['manifest_sha256'] ?? '') !== hash_file('sha256', $case.'/manifest.json')) $this->fail('manifest verification mismatch');
        $complete = false;
        if (file_exists($case.'/complete.json') || is_link($case.'/complete.json')) {
            $c = $this->readJson($case.'/complete.json');
            $entries = 0; foreach ($m['items'] as $item) $entries += count($item['entries']);
            $complete = ($c['removed_targets'] ?? null) === count($m['items']) && ($c['entries'] ?? null) === $entries
                && !file_exists($case.'/incomplete.json') && !is_link($case.'/incomplete.json');
        }
        return ['objects'=>$n, 'removal'=>$complete ? 'recorded complete' : 'incomplete or unconfirmed'];
    }
}
