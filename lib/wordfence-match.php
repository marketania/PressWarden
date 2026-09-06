<?php
require_once __DIR__ . '/json-object-stream.php';

if ($argc < 5) exit(2);
$scannerFile = $argv[1];
$productionFile = $argv[2];
$invFile = $argv[3];
$kevFile = $argv[4];

function pwf_clean($s) { return trim(preg_replace('/[\r\n\t|]+/', ' ', (string)$s)); }
function pwf_bound($v, $b, $inclusive, $lower) {
    if ($b === '*' || $b === '') return true;
    $c = version_compare($v, $b);
    return $lower ? ($inclusive ? $c >= 0 : $c > 0) : ($inclusive ? $c <= 0 : $c < 0);
}
function pwf_affected($v, $ranges) {
    foreach ((array)$ranges as $r) {
        $from = (string)($r['from_version'] ?? '*');
        $to = (string)($r['to_version'] ?? '*');
        $fi = (bool)($r['from_inclusive'] ?? true);
        $ti = (bool)($r['to_inclusive'] ?? true);
        if (pwf_bound($v, $from, $fi, true) && pwf_bound($v, $to, $ti, false)) return true;
    }
    return false;
}
function pwf_meta($r) {
    $copy = (array)($r['copyrights'] ?? array());
    $defiant = (array)($copy['defiant'] ?? array());
    $mitre = (array)($copy['mitre'] ?? array());
    $refs = (array)($r['references'] ?? array());
    return array(
        'cve' => strtoupper(pwf_clean($r['cve'] ?? '')),
        'rating' => strtolower((string)($r['cvss']['rating'] ?? '')),
        'score' => pwf_clean($r['cvss']['score'] ?? ''),
        'ref' => pwf_clean($refs[0] ?? ''),
        'def_notice' => pwf_clean($defiant['notice'] ?? ''),
        'def_url' => pwf_clean($defiant['license_url'] ?? ''),
        'mitre_notice' => pwf_clean($mitre['notice'] ?? ''),
        'mitre_url' => pwf_clean($mitre['license_url'] ?? '')
    );
}
function pwf_id($key, $r) { return pwf_clean($r['id'] ?? $key); }

$kev = array();
if (is_file($kevFile)) {
    $k = json_decode((string)@file_get_contents($kevFile), true);
    foreach ((array)($k['vulnerabilities'] ?? array()) as $r) {
        $c = strtoupper((string)($r['cveID'] ?? ''));
        if ($c !== '') $kev[$c] = true;
    }
}

$inv = array();
foreach (@file($invFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: array() as $line) {
    $p = explode('|', $line);
    if (count($p) < 5) continue;
    list($site, $type, $slug, $version, $status) = $p;
    $inv[strtolower($type) . '|' . strtolower($slug)][] = array($site, $type, $slug, $version, $status);
}

$matches = array();
try {
    foreach (presswarden_json_object_records($scannerFile) as $pair) {
        $key = $pair[0]; $scan = $pair[1];
        $id = pwf_id($key, $scan); if ($id === '') continue;
        $items = array();
        foreach ((array)($scan['software'] ?? array()) as $sw) {
            $type = strtolower((string)($sw['type'] ?? ''));
            $slug = strtolower((string)($sw['slug'] ?? ''));
            if ($type === 'core') $slug = 'wordpress';
            $ik = $type . '|' . $slug;
            if (empty($inv[$ik])) continue;
            foreach ($inv[$ik] as $item) {
                list($site, $itype, $islug, $version, $status) = $item;
                if ($version === '' || !pwf_affected($version, $sw['affected_versions'] ?? array())) continue;
                $items[] = array(
                    'site'=>$site, 'type'=>$itype, 'slug'=>$islug,
                    'version'=>$version, 'status'=>$status,
                    'patched'=>implode(',', array_map('strval', (array)($sw['patched_versions'] ?? array())))
                );
            }
        }
        if (!$items) continue;
        $matches[$id] = array(
            'info'=>(bool)($scan['informational'] ?? false),
            'scan'=>pwf_meta($scan), 'prod'=>null, 'items'=>$items
        );
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'scanner feed parse failed: ' . $e->getMessage() . "\n");
    exit(30);
}

if (!$matches) exit(0);

$scannerReal = @realpath($scannerFile);
$prodReal = is_file($productionFile) ? @realpath($productionFile) : false;
if ($prodReal && $scannerReal && $prodReal === $scannerReal) {
    foreach ($matches as $id => $m) $matches[$id]['prod'] = $m['scan'];
} elseif ($prodReal) {
    $remaining = count($matches);
    try {
        foreach (presswarden_json_object_records($productionFile) as $pair) {
            $id = pwf_id($pair[0], $pair[1]);
            if ($id === '' || !isset($matches[$id]) || $matches[$id]['prod'] !== null) continue;
            $matches[$id]['prod'] = pwf_meta($pair[1]);
            $remaining--;
            if ($remaining <= 0) break;
        }
    } catch (Throwable $e) {
        // Detection remains valid even if optional enrichment is unavailable.
        fwrite(STDERR, 'production enrichment warning: ' . $e->getMessage() . "\n");
    }
}

foreach ($matches as $id => $m) {
    $prod = is_array($m['prod']) ? $m['prod'] : array();
    $scan = $m['scan'];
    $meta = $prod ?: $scan;
    $cve = strtoupper((string)($meta['cve'] ?? ''));
    $rating = strtolower((string)($meta['rating'] ?? ''));
    $score = (string)($meta['score'] ?? '');
    $ref = (string)(($scan['ref'] ?? '') ?: ($meta['ref'] ?? ''));
    $isKev = $cve !== '' && isset($kev[$cve]);
    $enriched = $prod ? '1' : '0';
    foreach ($m['items'] as $item) {
        $kind = 'REVIEW';
        if ($m['info']) $kind = 'INFO';
        elseif ($isKev || $rating === 'critical' || $rating === 'high') $kind = 'ALERT';
        echo $kind,'|',pwf_clean($item['site']),'|',pwf_clean($item['type']),'|',pwf_clean($item['slug']),'|',
            pwf_clean($item['version']),'|',pwf_clean($item['status']),'|',$id,'|',$cve,'|',$score,'|',
            ($isKev?'1':'0'),'|',pwf_clean($item['patched']),'|',$ref,'|',$enriched,'|',
            (string)($meta['def_notice'] ?? ''),'|',(string)($meta['def_url'] ?? ''),'|',
            (string)($meta['mitre_notice'] ?? ''),'|',(string)($meta['mitre_url'] ?? ''),"\n";
    }
}
