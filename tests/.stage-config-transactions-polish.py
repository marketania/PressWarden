#!/usr/bin/env python3
from pathlib import Path
root = Path(__file__).resolve().parents[1]

def read(path): return (root/path).read_text()
def write(path,s): (root/path).write_text(s)
def replace_once(path,old,new):
    s=read(path)
    if old not in s: raise SystemExit(f'anchor not found {path}: {old[:90]!r}')
    write(path,s.replace(old,new,1))

replace_once('lib/config-transaction.php',
"""function pwct_same($a, $b, $identity = true) {
    if ($a['sha256'] !== $b['sha256'] || $a['size'] !== $b['size'] || $a['mode'] !== $b['mode']) {
        return false;
    }
    return !$identity || ($a['dev'] === $b['dev'] && $a['ino'] === $b['ino']);
}
""",
"""function pwct_same($a, $b, $identity = true) {
    if ($a['sha256'] !== $b['sha256'] || $a['size'] !== $b['size'] || $a['mode'] !== $b['mode']
        || $a['uid'] !== $b['uid'] || $a['gid'] !== $b['gid']) {
        return false;
    }
    return !$identity || ($a['dev'] === $b['dev'] && $a['ino'] === $b['ino']);
}
""")
replace_once('lib/config-transaction.php',
"""    if ($capture) {
        $temp = sys_get_temp_dir().'/presswarden-config-tx.'.bin2hex(random_bytes(8));
        $stdout = array('file', $temp, 'w');
    }
""",
"""    if ($capture) {
        $temp = sys_get_temp_dir().'/presswarden-config-tx.'.bin2hex(random_bytes(8));
        $oldMask = umask(0077);
        try {
            $captureHandle = @fopen($temp, 'xb');
        } finally {
            umask($oldMask);
        }
        if ($captureHandle === false) {
            return array(127, '');
        }
        @fclose($captureHandle);
        if (!@chmod($temp, 0600)) {
            @unlink($temp);
            return array(127, '');
        }
        $stdout = array('file', $temp, 'w');
    }
""")
replace_once('lib/config-transaction.php',
"""    @fclose($handle);
    @chmod($temp, $mode);

    clearstatcache(true, $config);
""",
"""    @fclose($handle);
    if (!@chmod($temp, $mode)) {
        @unlink($temp);
        pwct_fail('cannot preserve wp-config.php mode; live file was not modified');
    }
    $tempStat = pwct_regular($temp, PWCT_MAX_CONFIG, 'publication staging file');
    if ((int)$tempStat['uid'] !== (int)$expectedCurrent['uid']
        || (int)$tempStat['gid'] !== (int)$expectedCurrent['gid']) {
        @unlink($temp);
        pwct_fail('atomic replacement would change wp-config.php ownership; live file was not modified');
    }

    clearstatcache(true, $config);
""")
replace_once('lib/config-transaction.php',
"""    if ($published['sha256'] !== hash('sha256', $bytes)
        || $published['size'] !== strlen($bytes) || $published['mode'] !== $mode) {
""",
"""    if ($published['sha256'] !== hash('sha256', $bytes)
        || $published['size'] !== strlen($bytes) || $published['mode'] !== $mode
        || $published['uid'] !== $expectedCurrent['uid'] || $published['gid'] !== $expectedCurrent['gid']) {
""")
replace_once('tests/config-transaction.sh',
"""for name in a.com b.com c.com d.com e.com f.com; do make_site "$name"; done
""",
"""for name in a.com b.com c.com d.com e.com f.com; do make_site "$name"; done
chmod 640 "$T/sites/a.com/public_html/wp-config.php"
""")
replace_once('tests/config-transaction.sh',
"""grep -q 'DISALLOW_FILE_MODS\", true' "$T/sites/a.com/public_html/wp-config.php"
""",
"""grep -q 'DISALLOW_FILE_MODS\", true' "$T/sites/a.com/public_html/wp-config.php"
[ "$(stat -c %a "$T/sites/a.com/public_html/wp-config.php")" = 640 ]
""")
replace_once('docs/CONFIG-TRANSACTIONS.md',
"""9. Writes the verified staged bytes to a new temporary file in the live config directory and atomically renames it over `wp-config.php` only after one final source revalidation.
10. Verifies the published bytes, mode and requested WordPress constant.
""",
"""9. Writes the verified staged bytes to a new temporary file in the live config directory, requires that the replacement inode can preserve the original mode/owner/group, and atomically renames it over `wp-config.php` only after one final source revalidation.
10. Verifies the published bytes, mode, owner/group and requested WordPress constant.
""")
replace_once('CHANGELOG.md',
"""- Refuse symlink/hard-linked/oversized configs, owner mismatches where the effective UID can be checked, and any live source that changes during staging. External changes win rather than being overwritten.
""",
"""- Refuse symlink/hard-linked/oversized configs, replacement inodes that cannot preserve the live file's owner/group/mode, and any live source that changes during staging. External changes win rather than being overwritten.
""")
