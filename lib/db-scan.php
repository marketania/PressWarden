<?php
/** Bounded SELECT-only database inspection using the existing WordPress handle. */
require_once __DIR__.'/db-threat-classify.php';
final class PressWardenDbScan
{
    private $db; private $emit; private $maxRows; private $maxBytes;
    private $bytes = 0; private $counts = []; private $seen = []; private $errors = 0;
    public function __construct($db, $emit, $maxRows = 5000, $maxBytes = 33554432) {
        if (!is_object($db) || !is_callable([$db, 'get_results']) || !is_callable([$db, 'prepare'])) throw new RuntimeException('connection');
        if (!is_int($maxRows) || $maxRows < 1 || $maxRows > 50000 || !is_int($maxBytes) || $maxBytes < 1024 || $maxBytes > 268435456) throw new RuntimeException('configuration');
        $this->db = $db; $this->emit = $emit; $this->maxRows = $maxRows; $this->maxBytes = $maxBytes;
    }
    private function table($property) {
        $name = $this->db->$property ?? '';
        if (!is_string($name) || !preg_match('/^[A-Za-z0-9_]+$/D', $name)) throw new RuntimeException('table_identifier');
        return '`'.$name.'`';
    }
    private function query($sql) {
        $this->db->last_error = '';
        $rows = $this->db->get_results($sql, 'ARRAY_A');
        if ($this->db->last_error !== '' || !is_array($rows)) throw new RuntimeException('query');
        return $rows;
    }
    private function error($code, $source, $id = 0) {
        ++$this->errors; ($this->emit)(['ERROR', $code, $source, (string)$id]);
    }
    private function finding($kind, $rule, $source, $id) {
        $key = $source.':'.$id.':'.$rule;
        if (isset($this->seen[$key])) return;
        $this->seen[$key] = true; ($this->emit)(['FINDING', $kind, $rule, $source, (string)$id]);
    }
    private function scanTable($source) {
        $db = $this->db; $last = 0; $count = 0;
        $this->counts[$source] = 0;
        if ($source === 'admin') {
            $from = $this->table('usermeta').' um INNER JOIN '.$this->table('users').' u ON u.ID=um.user_id';
            $cursor = 'um.umeta_id'; $rowId = 'u.ID'; $body = 'um.meta_value';
            $fields = 'u.user_login AS login, u.user_email AS email';
            $capKey = (string)($db->prefix ?? '').'capabilities';
            $filter = $db->prepare('um.meta_key=%s AND um.meta_value LIKE %s', $capKey, '%administrator%');
        } else {
            $option = $source === 'option'; $from = $this->table($option ? 'options' : 'posts');
            $cursor = $rowId = $option ? 'option_id' : 'ID'; $body = $option ? 'option_value' : 'post_content';
            $fields = $option ? 'option_name AS name' : "'' AS name";
            $filter = 'LOWER('.$body.") REGEXP 'script|iframe|atob|fromcharcode|decodeuricomponent|unescape|[?]php|base64_decode|gzinflate'";
            if ($option) $filter .= " OR option_name REGEXP '^[0-9A-Fa-f]{32}$'";
        }
        if (!is_string($filter) || $filter === '') throw new RuntimeException('query');
        while (true) {
            // One lookahead row distinguishes exactly-at-limit from truncation.
            // Oversize values are not fetched; the NULL sentinel marks incomplete.
            $limit = min(16, $this->maxRows - $count + 1);
            $sql = "SELECT $cursor AS cursor_id, $rowId AS rid, $fields, OCTET_LENGTH($body) AS bytes, CASE WHEN OCTET_LENGTH($body)<=1048576 THEN $body ELSE NULL END AS body FROM $from WHERE $cursor>$last AND ($filter) ORDER BY $cursor ASC LIMIT $limit";
            $rows = $this->query($sql);
            if (!$rows) return;
            foreach ($rows as $row) {
                if ($count >= $this->maxRows) { $this->error('row_limit', $source); return; }
                foreach (['cursor_id','rid','bytes'] as $field) if (!isset($row[$field]) || !preg_match('/^[0-9]{1,18}$/D', (string)$row[$field])) throw new RuntimeException('row_format');
                $cursorId = (int)$row['cursor_id']; $id = (int)$row['rid']; $bytes = (int)$row['bytes'];
                if ($cursorId <= $last || $id <= 0) throw new RuntimeException('row_order');
                $last = $cursorId; $this->counts[$source] = ++$count;
                if ($bytes > 1048576) { $this->error('value_size', $source, $id); continue; }
                if ($this->bytes + $bytes > $this->maxBytes) { $this->error('byte_limit', $source, $id); return; }
                if (!array_key_exists('body', $row) || !is_string($row['body']) || strlen($row['body']) !== $bytes) throw new RuntimeException('row_format');
                $this->bytes += $bytes;
                try {
                    if ($source === 'admin') {
                        if (!presswarden_db_admin_role($row['body'])) continue;
                        $hit = presswarden_db_classify_admin($row['login'] ?? '', $row['email'] ?? '');
                        if ($hit) $this->finding($hit[0], $hit[1], $source, $id);
                    } else {
                        foreach (presswarden_db_classify_all($row['body'], $source, $row['name'] ?? '') as $hit) $this->finding($hit[0], $hit[1], $source, $id);
                    }
                } catch (Throwable $e) { $this->error('value_analysis', $source, $id); }
            }
            if (count($rows) < $limit) return;
        }
    }
    public function run() {
        $old = is_callable([$this->db, 'suppress_errors']) ? $this->db->suppress_errors(true) : null;
        try {
            foreach (['option','post','admin'] as $source) {
                try { $this->scanTable($source); }
                catch (Throwable $e) { $this->error('inspection', $source); }
            }
        } finally { if ($old !== null) $this->db->suppress_errors($old); }
        ($this->emit)(['DONE', (string)$this->errors, (string)count($this->seen), (string)array_sum($this->counts), (string)$this->bytes]);
        return $this->errors === 0 ? 0 : 2;
    }
}
