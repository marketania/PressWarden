<?php
/** Inert, bounded reader for common WordPress serialized scalars/arrays (MIT).
 * Objects, references and unsupported encodings are rejected, never instantiated.
 */
final class PressWardenDbValues
{
    private $source; private $pos = 0; private $nodes = 0;
    public function read($source) {
        if (strlen($source) > 1048576) throw new RuntimeException('value_size');
        $this->source = $source; $this->pos = $this->nodes = 0;
        $value = $this->value(0);
        if ($this->pos !== strlen($source)) throw new RuntimeException('value_format');
        return $value;
    }
    private function take($literal) {
        if (substr($this->source, $this->pos, strlen($literal)) !== $literal) throw new RuntimeException('value_format');
        $this->pos += strlen($literal);
    }
    private function number($end) {
        $at = strpos($this->source, $end, $this->pos);
        if ($at === false || $at - $this->pos > 12) throw new RuntimeException('value_format');
        $number = substr($this->source, $this->pos, $at - $this->pos);
        if (!preg_match('/^(?:0|[1-9][0-9]*)$/D', $number)) throw new RuntimeException('value_format');
        $this->pos = $at + strlen($end); return (int)$number;
    }
    private function value($depth) {
        if ($depth > 24 || ++$this->nodes > 12000) throw new RuntimeException('value_budget');
        $type = $this->source[$this->pos] ?? ''; ++$this->pos;
        if ($type === 'N') { $this->take(';'); return null; }
        $this->take(':');
        if ($type === 's') {
            $len = $this->number(':'); $this->take('"');
            if ($len > strlen($this->source) - $this->pos) throw new RuntimeException('value_format');
            $s = substr($this->source, $this->pos, $len); $this->pos += $len; $this->take('";'); return $s;
        }
        if ($type === 'a') {
            $count = $this->number(':'); $this->take('{'); $result = [];
            if ($count > 6000) throw new RuntimeException('value_budget');
            for ($i = 0; $i < $count; ++$i) {
                $key = $this->value($depth + 1);
                if ((!is_string($key) && !is_int($key)) || array_key_exists($key, $result)) throw new RuntimeException('value_format');
                $result[$key] = $this->value($depth + 1);
            }
            $this->take('}'); return $result;
        }
        if (!in_array($type, ['b', 'i', 'd'], true)) throw new RuntimeException('value_type');
        $end = strpos($this->source, ';', $this->pos);
        if ($end === false || $end - $this->pos > 40) throw new RuntimeException('value_format');
        $s = substr($this->source, $this->pos, $end - $this->pos); $this->pos = $end + 1;
        if ($type === 'b' && ($s === '0' || $s === '1')) return $s === '1';
        if ($type === 'i' && preg_match('/^-?(?:0|[1-9][0-9]*)$/D', $s)) return (int)$s;
        if ($type === 'd' && (is_numeric($s) || in_array($s, ['INF', '-INF', 'NAN'], true))) return 0.0;
        throw new RuntimeException('value_format');
    }
}

/** Keep independent builder/widget values separate; never concatenate their code. */
function presswarden_db_units($value) {
    $reader = new PressWardenDbValues(); $units = []; $nodes = 0;
    $walk = function ($v, $depth) use (&$walk, &$units, &$nodes, $reader) {
        if (++$nodes > 12000 || $depth > 24) throw new RuntimeException('value_budget');
        if (is_array($v)) { foreach ($v as $child) $walk($child, $depth + 1); return; }
        if (!is_string($v) || $v === '') return;
        if (strlen($v) > 1048576) throw new RuntimeException('value_size');
        if (preg_match('/^(?:[asibdOCRr]:|N;)/', $v)) { $walk($reader->read($v), $depth + 1); return; }
        $first = ltrim($v);
        if (($first[0] ?? '') === '{' || ($first[0] ?? '') === '[') {
            $json = json_decode($v, true, 25);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) { $walk($json, $depth + 1); return; }
            // Raw JS can begin with a block. Unambiguously JSON-looking broken
            // structures must not be mislabeled as successfully analyzed data.
            if (preg_match('/^[{[]\s*"/', $first)) throw new RuntimeException('value_format');
        }
        if (count($units) >= 2048) throw new RuntimeException('value_budget');
        $units[] = $v;
    };
    $walk((string)$value, 0); return $units;
}

function presswarden_db_admin_role($serialized) {
    $data = (new PressWardenDbValues())->read((string)$serialized);
    // WordPress assigns roles by top-level role key, not by searching values.
    // Even a false role-key value does not reliably remove inherited role caps.
    return is_array($data) && array_key_exists('administrator', $data);
}
