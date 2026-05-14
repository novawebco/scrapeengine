<?php
/**
 * Plugin Name: ScrapeEngine (V315.3)
 * Description: V315 Fixes: 1. Security - nonce + capability on all AJAX. 2. Retry counter (3x then skip). 3. Sitemap XML proper parse. 4. Duplicate cleaner batch delete + permanent. 5. Orphan finder batched. 6. Multilingual stop words. 7. Body selector improved fallback. 8. Progress bar with live stats. 9. Speed control slider.
 * Version: 315.3
 * Author: AI Assistant
 */

if (!defined('ABSPATH')) exit;

// ============================================================
// WORD COUNT COLUMN IN POST LIST
// ============================================================
add_filter('manage_posts_columns', function($cols) {
    $new = [];
    foreach ($cols as $key => $val) {
        $new[$key] = $val;
        if ($key === 'title') {
            $new['ans_word_count'] = '<span style="display:flex;align-items:center;gap:5px;">&#x1F4DD; Words</span>';
        }
    }
    return $new;
});

add_action('manage_posts_custom_column', function($col, $post_id) {
    if ($col !== 'ans_word_count') return;
    $content = get_post_field('post_content', $post_id);
    $text    = wp_strip_all_tags($content);
    $count   = $text ? str_word_count($text) : 0;

    if ($count >= 1500)      $color = '#22c55e';
    elseif ($count >= 800)   $color = '#f59e0b';
    else                     $color = '#94a3b8';

    echo '<span style="display:inline-block;background:' . esc_attr($color) . '22;color:' . esc_attr($color) . ';border:1px solid ' . esc_attr($color) . '55;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700;">' . esc_html(number_format_i18n($count)) . ' w</span>';
}, 10, 2);

add_filter('manage_edit-post_sortable_columns', function($cols) {
    $cols['ans_word_count'] = 'ans_word_count';
    return $cols;
});

// Sort by word count using meta value stored on save
add_action('save_post', function($post_id) {
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
    if (wp_is_post_revision($post_id) || wp_is_post_autosave($post_id)) return;
    $content = get_post_field('post_content', $post_id);
    $count   = str_word_count(wp_strip_all_tags($content));
    update_post_meta($post_id, '_ans_word_count', $count);
});

// On plugin activate — backfill word count meta for existing posts
add_action('admin_init', function() {
    if (!current_user_can('manage_options')) return;
    if (get_option('ans_wc_indexed')) return;
    global $wpdb;
    $ids = $wpdb->get_col("SELECT ID FROM $wpdb->posts WHERE post_status='publish' AND post_type='post' AND ID NOT IN (SELECT post_id FROM $wpdb->postmeta WHERE meta_key='_ans_word_count')");
    $done = 0;
    foreach ($ids as $id) {
        $c = str_word_count(wp_strip_all_tags(get_post_field('post_content', $id)));
        update_post_meta($id, '_ans_word_count', $c);
        if (++$done >= 200) break; // max 200 per load to avoid timeout
    }
    if (empty($ids) || count($ids) <= 200) update_option('ans_wc_indexed', 1);
});

// Apply sort query
add_action('pre_get_posts', function($query) {
    if (!is_admin() || !$query->is_main_query()) return;
    if ($query->get('orderby') === 'ans_word_count') {
        $query->set('meta_key', '_ans_word_count');
        $query->set('orderby', 'meta_value_num');
    }
});

// ============================================================
// SECURITY HELPER
// ============================================================
function ans_verify_request() {
    if (!check_ajax_referer('ans_nonce', 'nonce', false)) wp_send_json_error('Security check failed.', 403);
    if (!current_user_can('manage_options')) wp_send_json_error('Permission denied.', 403);
}

function ans_sanitize_choice($value, $allowed, $default) {
    if (is_array($value) || is_object($value)) return $default;
    $value = sanitize_key(wp_unslash($value));
    return in_array($value, $allowed, true) ? $value : $default;
}

function ans_sanitize_selector($value, $default = '') {
    if (is_array($value) || is_object($value)) return $default;
    $value = sanitize_text_field(wp_unslash($value));
    $value = substr(trim($value), 0, 120);
    if ($value === '') return $default;

    if (preg_match('/^(#[A-Za-z][A-Za-z0-9_-]*|\.[A-Za-z][A-Za-z0-9_-]*|[A-Za-z][A-Za-z0-9_-]*|\[[A-Za-z_:][-A-Za-z0-9_:.]*(=[\'"]?[^\'"\]\x00-\x1F]{1,80}[\'"]?)?\])$/', $value)) {
        return $value;
    }

    return $default;
}

function ans_xpath_literal($value) {
    $value = (string) $value;
    if (strpos($value, "'") === false) return "'" . $value . "'";
    if (strpos($value, '"') === false) return '"' . $value . '"';

    $parts = explode("'", $value);
    return "concat('" . implode("', \"'\", '", $parts) . "')";
}

function ans_selector_to_xpath($selector) {
    $selector = ans_sanitize_selector($selector, '');
    if ($selector === '') return '';

    if ($selector[0] === '#') {
        return "//*[@id=" . ans_xpath_literal(substr($selector, 1)) . "]";
    }

    if ($selector[0] === '.') {
        return "//*[contains(concat(' ', normalize-space(@class), ' '), " . ans_xpath_literal(' ' . substr($selector, 1) . ' ') . ")]";
    }

    if (preg_match('/^\[([A-Za-z_:][-A-Za-z0-9_:.]*)(?:=[\'"]?([^\'"\]]{1,80})[\'"]?)?\]$/', $selector, $m)) {
        $attr = $m[1];
        if (isset($m[2]) && $m[2] !== '') return "//*[@" . $attr . "=" . ans_xpath_literal($m[2]) . "]";
        return "//*[@" . $attr . "]";
    }

    if (preg_match('/^[A-Za-z][A-Za-z0-9_-]*$/', $selector)) {
        return '//' . strtolower($selector);
    }

    return '';
}

function ans_is_private_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}

function ans_normalize_host($host) {
    $host = strtolower(trim((string) $host, " \t\n\r\0\x0B."));
    if (function_exists('idn_to_ascii')) {
        $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
        $ascii = idn_to_ascii($host, 0, $variant);
        if ($ascii) $host = strtolower($ascii);
    }
    return $host;
}

function ans_host_resolves_publicly($host) {
    $host = ans_normalize_host($host);
    if ($host === '' || $host === 'localhost' || preg_match('/\.(localhost|local|internal|test|invalid|example)$/', $host)) {
        return false;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return !ans_is_private_ip($host);
    }

    $ips = [];
    $a_records = gethostbynamel($host);
    if (is_array($a_records)) $ips = array_merge($ips, $a_records);

    if (function_exists('dns_get_record')) {
        $aaaa_records = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa_records)) {
            foreach ($aaaa_records as $record) {
                if (!empty($record['ipv6'])) $ips[] = $record['ipv6'];
            }
        }
    }

    if (empty($ips)) return false;
    foreach (array_unique($ips) as $ip) {
        if (ans_is_private_ip($ip)) return false;
    }

    return true;
}

function ans_validate_scrape_url($url, $resolve_host = true, &$reason = '') {
    $reason = 'URL must be public http(s), not media/upload/private/internal.';
    if (is_array($url) || is_object($url)) return false;
    $url = trim((string) wp_unslash($url));
    if ($url === '') return false;

    $url = esc_url_raw($url, ['http', 'https']);
    $parts = wp_parse_url($url);
    if (empty($parts['scheme']) || empty($parts['host']) || !in_array(strtolower($parts['scheme']), ['http', 'https'], true)) return false;
    if (!empty($parts['user']) || !empty($parts['pass'])) return false;
    if (!empty($parts['port']) && !in_array((int) $parts['port'], [80, 443], true)) return false;
    if (!wp_http_validate_url($url)) return false;

    $decoded_path = isset($parts['path']) ? rawurldecode(strtolower($parts['path'])) : '';
    if (ans_is_media_url($url) || strpos($decoded_path, '/wp-content/uploads/') !== false) return false;
    if ($resolve_host && !ans_host_resolves_publicly($parts['host'])) return false;

    $reason = '';
    return $url;
}

function ans_is_internal_url($url) {
    if (is_array($url) || is_object($url)) return false;
    $url = esc_url_raw(wp_unslash($url), ['http', 'https']);
    $site_host = ans_normalize_host(wp_parse_url(home_url(), PHP_URL_HOST));
    $url_host  = ans_normalize_host(wp_parse_url($url, PHP_URL_HOST));
    return $url !== '' && $site_host !== '' && hash_equals($site_host, $url_host);
}

function ans_sanitize_option_value($option, $value) {
    switch ($option) {
        case 'ans_target_lang':
            return ans_sanitize_choice($value, ['select','pt','de','it','es','fr','en','hi','ru'], 'select');
        case 'ans_post_status':
            return ans_sanitize_choice($value, ['draft','publish'], 'publish');
        case 'ans_import_img':
            return ans_sanitize_choice($value, ['no','yes'], 'no');
        case 'ans_sitemap_url':
            $safe = ans_validate_scrape_url($value, false);
            return $safe ? $safe : '';
        case 'ans_title_sel':
            return ans_sanitize_selector($value, 'h1');
        case 'ans_body_sel':
            return ans_sanitize_selector($value, '.entry-content');
        case 'ans_scrape_delay':
            if (is_array($value) || is_object($value)) return 5;
            return min(30, max(2, absint($value)));
        case 'ans_manual_category':
        case 'ans_my_brand':
            if (is_array($value) || is_object($value)) return '';
            return substr(sanitize_text_field(wp_unslash($value)), 0, 120);
    }

    if (is_array($value) || is_object($value)) return '';
    return sanitize_text_field(wp_unslash($value));
}

// ============================================================
// ADMIN MENU
// ============================================================
add_action('admin_menu', 'ans_add_menu');
function ans_add_menu() {
    add_menu_page('ScrapeEngine V315', 'ScrapeEngine', 'manage_options', 'ai-news-scraper', 'ans_settings_page', 'dashicons-shield-alt', 100);
}

// ============================================================
// SETTINGS REGISTER
// ============================================================
add_action('admin_init', 'ans_register_settings');
function ans_register_settings() {
    $opts = ['ans_target_lang','ans_post_status','ans_sitemap_url','ans_title_sel','ans_body_sel','ans_import_img','ans_manual_category','ans_my_brand','ans_scrape_delay'];
    foreach ($opts as $o) {
        register_setting('ans_group', $o, [
            'sanitize_callback' => function($value) use ($o) {
                return ans_sanitize_option_value($o, $value);
            },
        ]);
    }
}

// ============================================================
// MULTILINGUAL STOP WORDS
// ============================================================
function ans_get_stop_words() {
    return array(
        // English
        'the','and','a','to','of','in','is','for','on','that','by','this','with','i','you','it','not','or','be','are','from','at','as','your','have','new','more','an','was','we','can','us','about','if','my','has','but','our','one','other','do','no','he','she','they','all','best','top','guide','review','how','tips','ways','improve','natural','remedies','why','what','check','out','help','helps','may','will','should','could','would','their','there','these','those','according','researchers','study','shows','result','published','english','language','says','dr','doctor','professor','university','journal','article','click','here','read','more','image','photo','credit','source','author','date','posted','advertisement','sponsored','related','posts','tags','categories','copyright','reserved','rights','which','been','also','when','than','then','into','over','after','before','between','very','just','like','get','got','use','used','using','make','made','take','taken','come','came','see','seen','know','known','think','thought','look','looked',
        // Italian
        'per','anche','con','che','del','della','dei','degli','delle','sul','sulla','sui','sugli','sulle','nel','nella','nei','negli','nelle','dal','dalla','dai','dagli','dalle','al','alla','ai','agli','alle','un','una','uno','questo','questa','questi','queste','sono','essere','avere','fare','si','non','ma','se','come','quando','dove','chi','cosa','quale','quali','suo','sua','suoi','sue','loro','ogni','tutto','tutti','tutte','tutta','solo','ancora','sempre','mai','qui','tra','fra','gli','dopo','prima','molto','poco','bene','male','poi','mentre','però','quindi','invece','anche','già','più','meno','fino','circa','contro','senza','verso','attraverso','durante','secondo','oltre','presso','rispetto',
        // Portuguese
        'para','com','que','uma','por','mais','seu','sua','dos','das','nos','nas','num','numa','pelo','pela','pelos','pelas','este','esta','estes','estas','esse','essa','esses','essas','aquele','aquela','ele','ela','eles','elas','nós','vós','muito','pouco','bem','mal','já','ainda','quando','onde','como','porque','mas','ou','nem','porém','então','assim','após','antes','depois','durante','entre','sobre','sob','até','desde','sem','contra','além','através','dentro','fora','junto','perto',
        // Spanish
        'para','con','que','una','por','más','sus','los','las','del','desde','hasta','entre','sobre','bajo','sin','contra','hacia','según','durante','mediante','excepto','salvo','incluso','pero','sino','aunque','porque','como','cuando','donde','quien','cual','cuyo','este','esta','estos','estas','ese','esa','esos','esas','aquel','aquella','ellos','ellas','nosotros','vosotros','muy','poco','bien','mal','ya','todavía','nunca','siempre','también',
        // German
        'der','die','das','den','dem','des','ein','eine','einer','einem','einen','eines','und','oder','aber','doch','wenn','weil','dass','damit','obwohl','während','jedoch','trotzdem','deshalb','deswegen','außerdem','sondern','entweder','weder','sowohl','zwar','allerdings','bereits','noch','auch','schon','immer','nie','nur','sehr','mehr','weniger','gut','schlecht','hier','dort','jetzt','dann','danach','vorher','zwischen','über','unter','neben','hinter','vor','nach','bei','mit','ohne','gegen','durch','für','um','aus','von','zu','an','auf','in','an',
        // French
        'pour','avec','que','une','par','plus','sur','dans','sont','être','avoir','faire','dit','cette','tout','mais','ou','donc','car','comme','quand','où','qui','quel','quelle','quels','quelles','celui','celle','ceux','celles','leur','leurs','notre','votre','très','peu','bien','mal','déjà','encore','toujours','jamais','aussi','puis','alors','ainsi','après','avant','pendant','depuis','jusqu','entre','parmi','contre','sans','vers','chez','selon','malgré','grâce'
    );
}

// ============================================================
// LINKGRAPH - ENTERPRISE 3+ WORD INTERNAL LINKING
// ============================================================
if (!defined('ANS_LG_MIN_ANCHOR_WORDS')) define('ANS_LG_MIN_ANCHOR_WORDS', 3);
if (!defined('ANS_LG_MAX_ANCHOR_WORDS')) define('ANS_LG_MAX_ANCHOR_WORDS', 6);
if (!defined('ANS_LG_MAX_RULES_PER_POST')) define('ANS_LG_MAX_RULES_PER_POST', 8);
if (!defined('ANS_LG_MAX_LINKS_PER_POST')) define('ANS_LG_MAX_LINKS_PER_POST', 5);

function ans_lg_lower($text) {
    return function_exists('mb_strtolower') ? mb_strtolower($text, 'UTF-8') : strtolower($text);
}

function ans_lg_strlen($text) {
    return function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : strlen($text);
}

function ans_lg_normalize_text($text) {
    $text = html_entity_decode(wp_strip_all_tags((string)$text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = ans_lg_lower($text);
    $text = preg_replace('/https?:\/\/\S+|www\.\S+/iu', ' ', $text);
    $text = preg_replace('/[^\p{L}\p{N}\s]+/u', ' ', $text);
    $text = preg_replace('/\s+/u', ' ', trim($text));
    return $text ?: '';
}

function ans_lg_words($text) {
    $text = ans_lg_normalize_text($text);
    if ($text === '') return [];
    return array_values(array_filter(preg_split('/\s+/u', $text), function($word) {
        return ans_lg_strlen($word) > 1;
    }));
}

function ans_lg_clean_phrase($phrase) {
    return trim(implode(' ', ans_lg_words($phrase)));
}

function ans_lg_phrase_word_count($phrase) {
    return count(ans_lg_words($phrase));
}

function ans_lg_phrase_allowed($phrase) {
    $words = ans_lg_words($phrase);
    $count = count($words);
    if ($count < ANS_LG_MIN_ANCHOR_WORDS || $count > ANS_LG_MAX_ANCHOR_WORDS) return false;
    if (ans_lg_strlen(implode('', $words)) < 12) return false;

    $stop = ans_get_stop_words();
    if (in_array($words[0], $stop, true) || in_array(end($words), $stop, true)) return false;

    $meaningful = 0;
    foreach ($words as $word) {
        if (in_array($word, $stop, true)) continue;
        if (ans_lg_strlen($word) >= 4) $meaningful++;
    }
    if ($meaningful < 2) return false;

    $joined = implode(' ', $words);
    if (preg_match('/\b(click here|read more|source author|image credit|related posts|table of contents)\b/iu', $joined)) return false;
    return true;
}

function ans_lg_add_phrase(&$phrases, $phrase, $score, $source) {
    $phrase = ans_lg_clean_phrase($phrase);
    if (!ans_lg_phrase_allowed($phrase)) return;
    $key = ans_lg_lower($phrase);
    if (!isset($phrases[$key]) || intval($phrases[$key]['score']) < intval($score)) {
        $phrases[$key] = ['phrase' => $phrase, 'score' => intval($score), 'source' => $source, 'words' => ans_lg_phrase_word_count($phrase)];
    }
}

function ans_lg_compact_phrases($phrases, $limit = ANS_LG_MAX_RULES_PER_POST) {
    uasort($phrases, function($a, $b) {
        if ($a['score'] == $b['score']) return $b['words'] <=> $a['words'];
        return $b['score'] <=> $a['score'];
    });

    $selected = [];
    foreach ($phrases as $key => $meta) {
        $covered = false;
        foreach ($selected as $existing_key => $existing) {
            if (strpos($existing_key, $key) !== false || strpos($key, $existing_key) !== false) {
                $covered = true;
                break;
            }
        }
        if ($covered) continue;
        $selected[$key] = $meta;
        if (count($selected) >= $limit) break;
    }
    return $selected;
}

function ans_lg_extract_anchor_phrases($content, $post_title) {
    $phrases = [];
    $title_words = ans_lg_words($post_title);
    if (count($title_words) >= ANS_LG_MIN_ANCHOR_WORDS) {
        ans_lg_add_phrase($phrases, implode(' ', array_slice($title_words, 0, min(ANS_LG_MAX_ANCHOR_WORDS, count($title_words)))), 130, 'title');
        for ($i = 0; $i <= count($title_words) - ANS_LG_MIN_ANCHOR_WORDS; $i++) {
            for ($len = ANS_LG_MAX_ANCHOR_WORDS; $len >= ANS_LG_MIN_ANCHOR_WORDS; $len--) {
                if (!isset($title_words[$i + $len - 1])) continue;
                ans_lg_add_phrase($phrases, implode(' ', array_slice($title_words, $i, $len)), 100 + ($len * 6), 'title');
            }
        }
    }

    if (preg_match_all('/<h[2-4][^>]*>(.*?)<\/h[2-4]>/isu', $content, $heads)) {
        foreach ($heads[1] as $heading) {
            $words = ans_lg_words($heading);
            for ($i = 0; $i <= count($words) - ANS_LG_MIN_ANCHOR_WORDS; $i++) {
                for ($len = ANS_LG_MAX_ANCHOR_WORDS; $len >= ANS_LG_MIN_ANCHOR_WORDS; $len--) {
                    if (!isset($words[$i + $len - 1])) continue;
                    ans_lg_add_phrase($phrases, implode(' ', array_slice($words, $i, $len)), 78 + ($len * 5), 'heading');
                }
            }
        }
    }

    $words = ans_lg_words($content);
    $counts = [];
    $max = count($words);
    for ($i = 0; $i < $max; $i++) {
        for ($len = ANS_LG_MAX_ANCHOR_WORDS; $len >= ANS_LG_MIN_ANCHOR_WORDS; $len--) {
            if (!isset($words[$i + $len - 1])) continue;
            $phrase = implode(' ', array_slice($words, $i, $len));
            if (!ans_lg_phrase_allowed($phrase)) continue;
            $counts[$phrase] = ($counts[$phrase] ?? 0) + 1;
        }
    }

    foreach ($counts as $phrase => $freq) {
        $words_count = ans_lg_phrase_word_count($phrase);
        if ($freq < 2 && $words_count < 4) continue;
        ans_lg_add_phrase($phrases, $phrase, ($freq * 12) + ($words_count * 8), 'body');
    }

    return ans_lg_compact_phrases($phrases);
}

function ans_lg_phrase_regex($phrase) {
    $words = ans_lg_words($phrase);
    if (count($words) < ANS_LG_MIN_ANCHOR_WORDS) return false;
    $escaped = array_map(function($word) { return preg_quote($word, '/'); }, $words);
    return '/(?<![\p{L}\p{N}])(' . implode('[\s\x{00A0}\-\x{2010}-\x{2015}]+', $escaped) . ')(?![\p{L}\p{N}])/iu';
}

function ans_lg_content_has_phrase($content, $phrase) {
    $pattern = ans_lg_phrase_regex($phrase);
    return $pattern && preg_match($pattern, wp_strip_all_tags($content));
}

function ans_lg_content_has_link_to($content, $url) {
    return strpos($content, 'href="' . esc_url($url) . '"') !== false || strpos($content, "href='" . esc_url($url) . "'") !== false;
}

function ans_lg_title_key($title) {
    $title = html_entity_decode(wp_strip_all_tags((string)$title), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $title = preg_replace('/\s+/u', ' ', trim($title));
    return ans_lg_lower($title);
}

function ans_lg_get_title_map() {
    static $title_map = null;
    if ($title_map !== null) return $title_map;

    global $wpdb;
    $title_map = [];
    $rows = $wpdb->get_results(
        "SELECT ID, post_title FROM $wpdb->posts WHERE post_type='post' AND post_status='publish' AND post_title<>'' ORDER BY ID ASC"
    );

    foreach ($rows as $row) {
        $key = ans_lg_title_key($row->post_title);
        if ($key === '' || isset($title_map[$key])) continue;
        $title_map[$key] = [
            'id' => intval($row->ID),
            'title' => $row->post_title,
            'url' => get_permalink($row->ID),
        ];
    }

    return $title_map;
}

function ans_lg_related_heading_pattern() {
    return '(?:related\s+(?:articles?|posts?)|verwandte\s+artikel|weitere\s+artikel|ahnliche\s+artikel|articulos\s+relacionados|articles\s+connexes|articles\s+lies|articoli\s+correlati|artigos\s+relacionados)';
}

function ans_lg_link_related_title_list($list_html, $current_post_id, &$linked_count) {
    $title_map = ans_lg_get_title_map();
    if (empty($title_map)) return $list_html;

    return preg_replace_callback('/<li\b([^>]*)>(.*?)<\/li>/isu', function($m) use ($title_map, $current_post_id, &$linked_count) {
        $attrs = $m[1];
        $inner = $m[2];
        if (preg_match('/<a\b/i', $inner)) return $m[0];

        $key = ans_lg_title_key($inner);
        if ($key === '' || empty($title_map[$key])) return $m[0];

        $target = $title_map[$key];
        if (intval($target['id']) === intval($current_post_id)) return $m[0];

        $linked_count++;
        return '<li' . $attrs . '><a href="' . esc_url($target['url']) . '" class="ans-related-title-link" title="' . esc_attr($target['title']) . '" style="color:#1e73be;font-weight:600;text-decoration:underline;">' . $inner . '</a></li>';
    }, $list_html);
}

function ans_lg_link_related_titles($content, $current_post_id = 0, &$linked_count = null) {
    $linked = 0;
    $heading = ans_lg_related_heading_pattern();
    $heading_block = '(?:<(?:p|h2|h3|h4|h5|h6)\b[^>]*>\s*(?:<(?:strong|b)\b[^>]*>\s*)?' . $heading . '\s*:?\s*(?:<\/(?:strong|b)>\s*)?<\/(?:p|h2|h3|h4|h5|h6)>\s*|(?:<(?:strong|b)\b[^>]*>\s*)?' . $heading . '\s*:?\s*(?:<\/(?:strong|b)>\s*)?)';
    $pattern = '/(' . $heading_block . ')(\s*<(?:ul|ol)\b[^>]*>.*?<\/(?:ul|ol)>)/isu';

    $content = preg_replace_callback($pattern, function($m) use ($current_post_id, &$linked) {
        return $m[1] . ans_lg_link_related_title_list($m[2], $current_post_id, $linked);
    }, $content);

    $linked_count = $linked;
    return $content;
}

function ans_lg_count_internal_links($content) {
    if (!preg_match_all('/<a\b[^>]+href=["\']([^"\']+)["\']/i', $content, $matches)) return 0;
    $home = untrailingslashit(home_url());
    $count = 0;
    foreach ($matches[1] as $href) {
        if (strpos(untrailingslashit($href), $home) === 0 || url_to_postid($href)) $count++;
    }
    return $count;
}

function ans_lg_insert_link_once($content, $keyword, $url, $title) {
    if (!ans_lg_phrase_allowed($keyword) || ans_lg_content_has_link_to($content, $url)) return [$content, false];
    $pattern = ans_lg_phrase_regex($keyword);
    if (!$pattern) return [$content, false];

    $parts = preg_split('/(<[^>]+>)/u', $content, -1, PREG_SPLIT_DELIM_CAPTURE);
    if (!$parts) $parts = [$content];

    $blocked_tags = ['a','h1','h2','h3','h4','h5','h6','script','style','noscript','textarea','select','button','form','code','pre'];
    $eligible_tags = ['p','li','blockquote'];
    $has_eligible_blocks = preg_match('/<\s*(p|li|blockquote)\b/i', $content);
    $blocked = 0;
    $eligible = 0;
    $changed = false;
    $out = '';

    foreach ($parts as $part) {
        if (preg_match('/^<\s*\/\s*([a-z0-9]+)\b/i', $part, $close)) {
            $tag = strtolower($close[1]);
            if (in_array($tag, $blocked_tags, true)) $blocked = max(0, $blocked - 1);
            if (in_array($tag, $eligible_tags, true)) $eligible = max(0, $eligible - 1);
            $out .= $part;
            continue;
        }
        if (preg_match('/^<\s*([a-z0-9]+)\b/i', $part, $open)) {
            $tag = strtolower($open[1]);
            $is_self_closing = preg_match('/\/\s*>$/', $part);
            if (in_array($tag, $blocked_tags, true) && !$is_self_closing) $blocked++;
            if (in_array($tag, $eligible_tags, true) && !$is_self_closing) $eligible++;
            $out .= $part;
            continue;
        }
        if (!$changed && $blocked === 0 && (!$has_eligible_blocks || $eligible > 0)) {
            $rep = '<a href="' . esc_url($url) . '" class="ans-smart-link" title="' . esc_attr($title) . '" style="color:#1e73be;font-weight:600;text-decoration:underline;">$1</a>';
            $new = preg_replace($pattern, $rep, $part, 1, $hits);
            if ($hits > 0) {
                $part = $new;
                $changed = true;
            }
        }
        $out .= $part;
    }

    return [$out, $changed];
}

function ans_lg_get_link_suggestions($post, $map, $max = ANS_LG_MAX_LINKS_PER_POST) {
    if (!$post || empty($map)) return [];
    $content = $post->post_content;
    $available = ANS_LG_MAX_LINKS_PER_POST - ans_lg_count_internal_links($content);
    if ($available <= 0) return [];

    $source_topics = ans_get_content_topics($content);
    $source_url = get_permalink($post->ID);
    $suggestions = [];
    $used_targets = [];

    foreach ($map as $keyword => $data) {
        if (!ans_lg_phrase_allowed($keyword)) continue;
        if (empty($data['post_id']) || intval($data['post_id']) === intval($post->ID)) continue;
        if (!empty($data['url']) && $source_url === $data['url']) continue;
        if (empty($data['url']) || !ans_is_internal_url($data['url']) || ans_lg_content_has_link_to($content, $data['url'])) continue;
        if (!ans_lg_content_has_phrase($content, $keyword)) continue;

        $target_topics = $data['topics'] ?? [];
        $overlap = count(array_intersect($source_topics, $target_topics));
        $words = ans_lg_phrase_word_count($keyword);
        if ($overlap < 1 && $words < 4) continue;

        $phrase_score = intval($data['score'] ?? 0);
        $score = ($overlap * 24) + ($words * 9) + min(35, intval($phrase_score / 4));
        if ($score < 44) continue;

        $target_key = $data['url'];
        if (isset($used_targets[$target_key])) continue;
        $used_targets[$target_key] = true;

        $suggestions[] = [
            'keyword' => $keyword,
            'target' => $data['title'] ?? '',
            'target_url' => $data['url'],
            'post_id' => $post->ID,
            'score' => min(99, $score),
            'overlap' => $overlap,
            'words' => $words,
            'source' => $data['source'] ?? 'body',
        ];
    }

    usort($suggestions, function($a, $b) { return $b['score'] <=> $a['score']; });
    return array_slice($suggestions, 0, min($max, $available));
}

// INTERLINKING - 3+ WORD PHRASE RULES
// ============================================================
function ans_extract_keywords($content, $post_title) {
    return array_keys(ans_lg_extract_anchor_phrases($content, $post_title));
}

function ans_get_content_topics($content) {
    $stop = ans_get_stop_words();
    $words = array_filter(ans_lg_words($content), function($word) use ($stop) {
        return ans_lg_strlen($word) >= 4 && !in_array($word, $stop, true);
    });
    $counts = array_count_values($words);
    arsort($counts);
    return array_slice(array_keys($counts), 0, 16);
}

// LINK SCAN
add_action('wp_ajax_ans_link_scan', 'ans_link_scan_process');
function ans_link_scan_process() {
    ans_verify_request();
    $offset = absint($_POST['offset'] ?? 0);
    $limit  = 50;
    $counts = wp_count_posts('post');
    $total  = intval($counts->publish ?? 0);
    $posts  = get_posts(['post_type' => 'post', 'post_status' => 'publish', 'posts_per_page' => $limit, 'offset' => $offset]);
    $map    = ($offset === 0) ? [] : get_option('ans_link_map', []);
    if (!is_array($map)) $map = [];

    foreach ($posts as $p) {
        $phrases = ans_lg_extract_anchor_phrases($p->post_content, $p->post_title);
        $topics  = ans_get_content_topics($p->post_content);
        $url     = get_permalink($p->ID);
        foreach ($phrases as $phrase => $meta) {
            $score = intval($meta['score']);
            if (!isset($map[$phrase]) || intval($map[$phrase]['score'] ?? 0) < $score) {
                $map[$phrase] = [
                    'url' => $url,
                    'title' => $p->post_title,
                    'topics' => $topics,
                    'post_id' => $p->ID,
                    'score' => $score,
                    'words' => intval($meta['words']),
                    'source' => $meta['source'],
                ];
            }
        }
    }

    uasort($map, function($a, $b) {
        if (($a['words'] ?? 0) === ($b['words'] ?? 0)) return intval($b['score'] ?? 0) <=> intval($a['score'] ?? 0);
        return intval($b['words'] ?? 0) <=> intval($a['words'] ?? 0);
    });

    update_option('ans_link_map', $map);
    update_option('ans_link_stats', ['rules' => count($map), 'scanned' => min($offset + count($posts), $total), 'total' => $total]);
    if ($offset === 0) update_option('ans_last_scan', current_time('mysql'));
    wp_send_json_success(['next_offset' => $offset + $limit, 'total' => $total, 'rules' => count($map)]);
}

// LINK REPORT
add_action('wp_ajax_ans_link_report', 'ans_link_report_process');
function ans_link_report_process() {
    ans_verify_request();
    $offset = absint($_POST['offset'] ?? 0);
    $limit  = 50;
    $posts  = get_posts(['post_type' => 'post', 'post_status' => 'publish', 'posts_per_page' => $limit, 'offset' => $offset]);
    $map    = get_option('ans_link_map', []);
    if (!is_array($map)) $map = [];
    $html   = '';

    foreach ($posts as $post) {
        $links = ans_lg_get_link_suggestions($post, $map, ANS_LG_MAX_LINKS_PER_POST);
        foreach ($links as $link) {
            $strength = '<strong style="color:#f8fafc;">'.$link['score'].'</strong><span style="color:#64748b;"> / 99</span><br><span style="font-size:10px;color:#94a3b8;">'.$link['words'].' words, '.$link['overlap'].' topic hits</span>';
            $html .= '<tr>
                <td><input type="checkbox" class="cb-row" data-post-id="'.intval($link['post_id']).'" data-keyword="'.esc_attr($link['keyword']).'" data-url="'.esc_attr($link['target_url']).'" data-title="'.esc_attr($link['target']).'" value="'.esc_attr($link['keyword']).'"></td>
                <td><a href="'.esc_url(get_permalink($post->ID)).'" target="_blank" style="color:#cbd5e1;">'.esc_html($post->post_title).'</a></td>
                <td><span style="border-bottom:1px solid #3b82f6;color:#93c5fd;">'.esc_html($link['keyword']).'</span><br><span style="font-size:10px;color:#64748b;">'.esc_html(strtoupper($link['source'])).' phrase</span></td>
                <td><a href="'.esc_url($link['target_url']).'" target="_blank" style="color:#22c55e;">'.esc_html($link['target']).'</a></td>
                <td style="font-size:11px;">'.$strength.'</td>
                <td style="text-align:center;"><span class="delete-icon" onclick="deleteLinkSingle(\''.esc_js($link['keyword']).'\')">&times;</span></td>
            </tr>';
        }
    }

    if (empty($html)) {
        $html = '<tr><td colspan="6" style="text-align:center;padding:30px;color:#94a3b8;">No 3+ word link opportunities found in posts '.$offset.' to '.($offset+$limit).'. Load the next batch or rebuild the graph.</td></tr>';
    }
    wp_send_json_success(['html' => $html, 'next_offset' => $offset + $limit, 'current_range' => "$offset - ".($offset + count($posts))]);
}
/*
        foreach ($found as $link) {
            $stars = str_repeat('★', min($link['mc'], 5)) . str_repeat('☆', max(0, 5 - $link['mc']));
            $html .= '<tr>
                <td><input type="checkbox" class="cb-row" data-post-id="'.$link['post_id'].'" data-keyword="'.esc_attr($link['keyword']).'" data-url="'.esc_attr($link['target_url']).'" data-title="'.esc_attr($link['target']).'" value="'.esc_attr($link['keyword']).'"></td>
                <td><a href="'.$post_url.'" target="_blank" style="color:#cbd5e1;">'.esc_html($post->post_title).'</a></td>
                <td><span style="border-bottom:1px solid #3b82f6;color:#93c5fd;">'.esc_html($link['keyword']).'</span></td>
                <td><a href="'.esc_url($link['target_url']).'" target="_blank" style="color:#22c55e;">'.esc_html($link['target']).'</a></td>
                <td style="color:#f59e0b;font-size:11px;">'.$stars.'</td>
                <td style="text-align:center;"><span class="delete-icon" onclick="deleteLinkSingle(\''.esc_attr($link['keyword']).'\')">&times;</span></td>
            </tr>';
        }
    }

    if (empty($html)) {
        $html = '<tr><td colspan="6" style="text-align:center;padding:30px;color:#94a3b8;">No links found in posts '.$offset.' to '.($offset+$limit).'. Click <strong>Check Next 50</strong>.</td></tr>';
    }
    wp_send_json_success(['html' => $html, 'next_offset' => $offset + $limit, 'current_range' => "$offset - ".($offset + count($posts))]);
*/

// APPLY LINKS PERMANENTLY
add_action('wp_ajax_ans_apply_links', 'ans_apply_links_process');
function ans_apply_links_process() {
    ans_verify_request();
    $items = $_POST['items'] ?? [];
    if (!is_array($items)) $items = [];
    if (empty($items)) wp_send_json_error('No items selected.');

    $applied = 0;
    $skipped = 0;
    $by_post = [];
    foreach ($items as $item) {
        $pid = intval($item['post_id'] ?? 0);
        if ($pid > 0) $by_post[$pid][] = $item;
    }

    foreach ($by_post as $post_id => $links) {
        $post = get_post($post_id);
        if (!$post || !current_user_can('edit_post', $post_id)) { $skipped += count($links); continue; }

        $content = $post->post_content;
        $added = 0;
        $existing_internal = ans_lg_count_internal_links($content);

        foreach ($links as $link) {
            if (($existing_internal + $added) >= ANS_LG_MAX_LINKS_PER_POST) { $skipped++; continue; }

            $kw = sanitize_text_field(wp_unslash($link['keyword'] ?? ''));
            $url = esc_url_raw(wp_unslash($link['url'] ?? ''));
            $title = sanitize_text_field(wp_unslash($link['title'] ?? ''));

            if (!ans_lg_phrase_allowed($kw) || empty($url) || !ans_is_internal_url($url)) { $skipped++; continue; }
            list($content, $changed) = ans_lg_insert_link_once($content, $kw, $url, $title);
            if ($changed) { $applied++; $added++; }
            else $skipped++;
        }

        if ($added > 0) wp_update_post(['ID' => $post_id, 'post_content' => $content]);
    }

    wp_send_json_success("Applied: $applied 3+ word links. Skipped: $skipped.");
}

add_action('wp_ajax_ans_apply_all_links', 'ans_apply_all_links_process');
function ans_apply_all_links_process() {
    ans_verify_request();

    $offset = absint($_POST['offset'] ?? 0);
    $limit  = 25;
    $map    = get_option('ans_link_map', []);
    if (!is_array($map)) $map = [];

    $counts = wp_count_posts('post');
    $total  = intval($counts->publish ?? 0);
    $posts  = get_posts(['post_type' => 'post', 'post_status' => 'publish', 'posts_per_page' => $limit, 'offset' => $offset]);

    $applied = 0;
    $related = 0;
    $skipped = 0;

    foreach ($posts as $post) {
        if (!current_user_can('edit_post', $post->ID)) { $skipped++; continue; }
        $content = $post->post_content;
        $added = 0;
        $related_added = 0;
        $content = ans_lg_link_related_titles($content, $post->ID, $related_added);
        $related += $related_added;
        $links = ans_lg_get_link_suggestions($post, $map, ANS_LG_MAX_LINKS_PER_POST);

        foreach ($links as $link) {
            list($content, $changed) = ans_lg_insert_link_once($content, $link['keyword'], $link['target_url'], $link['target']);
            if ($changed) { $applied++; $added++; }
            else $skipped++;
        }

        if ($added > 0 || $related_added > 0) wp_update_post(['ID' => $post->ID, 'post_content' => $content]);
    }

    $next = $offset + $limit;
    wp_send_json_success([
        'done' => $next >= $total,
        'next_offset' => $next,
        'total' => $total,
        'processed' => min($next, $total),
        'applied' => $applied,
        'related' => $related,
        'skipped' => $skipped,
    ]);
}

// ORPHAN FINDER - BATCHED to avoid memory crash
add_action('wp_ajax_ans_find_orphans', 'ans_find_orphans_process');
function ans_find_orphans_process() {
    ans_verify_request();
    $offset = absint($_POST['offset'] ?? 0);
    $limit  = 100;
    $home   = home_url();
    $home_pattern = preg_quote($home, '/');

    // Get all post URLs for fast lookup
    global $wpdb;
    if ($offset == 0) {
        delete_transient('ans_linked_ids');
    }
    $linked_ids = get_transient('ans_linked_ids') ?: [];

    $posts = get_posts(['post_type' => 'post', 'post_status' => 'publish', 'posts_per_page' => $limit, 'offset' => $offset, 'fields' => 'ids']);

    foreach ($posts as $pid) {
        $post = get_post($pid);
        preg_match_all('/href=["\'](' . $home_pattern . '[^"\']*)["\']/i', $post->post_content, $m);
        foreach ($m[1] as $href) {
            $fid = url_to_postid($href);
            if ($fid && $fid != $pid) $linked_ids[$fid] = true;
        }
    }

    set_transient('ans_linked_ids', $linked_ids, 300);
    $total = wp_count_posts()->publish;

    if (($offset + $limit) < $total) {
        wp_send_json_success(['done' => false, 'next_offset' => $offset + $limit, 'total' => $total, 'scanned' => $offset + count($posts)]);
    }

    // Final pass — find orphans
    $all_ids = $wpdb->get_col("SELECT ID FROM $wpdb->posts WHERE post_status='publish' AND post_type='post'");
    $orphans = [];
    foreach ($all_ids as $pid) {
        if (!isset($linked_ids[$pid])) {
            $p = get_post($pid);
            $orphans[] = ['id' => absint($pid), 'title' => $p->post_title, 'url' => esc_url_raw(get_permalink($pid))];
        }
    }
    delete_transient('ans_linked_ids');
    wp_send_json_success(['done' => true, 'orphans' => $orphans, 'count' => count($orphans)]);
}

add_action('wp_ajax_ans_clear_links',      function() { ans_verify_request(); delete_option('ans_link_map'); delete_option('ans_last_scan'); delete_option('ans_link_stats'); wp_send_json_success(); });
add_action('wp_ajax_ans_delete_link_keys', 'ans_delete_link_keys_process');
function ans_delete_link_keys_process() {
    ans_verify_request();
    $keys = $_POST['keywords'] ?? [];
    if (!is_array($keys)) $keys = [$keys];
    $map  = get_option('ans_link_map', []);
    if (!is_array($map)) $map = [];
    foreach ($keys as $k) {
        $k = ans_lg_lower(ans_lg_clean_phrase(wp_unslash($k)));
        if ($k !== '') unset($map[$k]);
    }
    update_option('ans_link_map', $map);
    wp_send_json_success();
}

add_action('wp_ajax_ans_toggle_linking', function() {
    ans_verify_request();
    $new = (get_option('ans_linking_enabled', 'yes') === 'yes') ? 'no' : 'yes';
    update_option('ans_linking_enabled', $new);
    wp_send_json_success($new);
});

// FRONTEND LINKER — max 5, 1 topic match
add_filter('the_content', 'ans_pro_linker');
function ans_pro_linker($content) {
    if (!is_singular('post') || get_option('ans_linking_enabled', 'yes') === 'no') return $content;
    $post = get_post();
    if (!$post) return $content;

    $content = ans_lg_link_related_titles($content, $post->ID);

    $map = get_option('ans_link_map', []);
    if (!is_array($map)) $map = [];
    if (empty($map)) return $content;

    $post->post_content = $content;
    $suggestions = ans_lg_get_link_suggestions($post, $map, ANS_LG_MAX_LINKS_PER_POST);
    foreach ($suggestions as $link) {
        list($content, $changed) = ans_lg_insert_link_once($content, $link['keyword'], $link['target_url'], $link['target']);
    }
    return $content;
}

// ============================================================
// MEDIA URL HELPER
// ============================================================
function ans_is_media_url($url) {
    if (is_array($url) || is_object($url)) return true;
    $path = wp_parse_url((string) $url, PHP_URL_PATH);
    $ext = strtolower(pathinfo((string) $path, PATHINFO_EXTENSION));
    return in_array($ext, ['jpg','jpeg','png','gif','webp','svg','bmp','ico','mp4','mp3','wav','ogg','pdf','zip','rar','css','js','woff','woff2','ttf','eot','xml','json']);
}

function ans_queue_remove_current($url = '') {
    $q = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    if (empty($q)) return;

    if ($url && isset($q[0]) && $q[0] !== $url) {
        $idx = array_search($url, $q, true);
        if ($idx !== false) unset($q[$idx]);
        else array_shift($q);
    } else {
        array_shift($q);
    }

    update_option('ans_queue', array_values($q));
}

function ans_quality_hold_items() {
    $items = get_option('ans_quality_hold_urls', []);
    return is_array($items) ? $items : [];
}

function ans_quality_hold_save($items) {
    if (!is_array($items)) $items = [];
    update_option('ans_quality_hold_urls', array_values($items));
}

function ans_quality_hold_record($url, $reason, $type = 'quality') {
    $url = ans_validate_scrape_url($url, false);
    if (!$url) return;

    $items = ans_quality_hold_items();
    $now   = current_time('mysql');
    $key   = md5(strtolower(trim($url)));
    $found = false;

    foreach ($items as &$item) {
        if (empty($item['key']) && !empty($item['url'])) $item['key'] = md5(strtolower(trim($item['url'])));
        if (!empty($item['key']) && $item['key'] === $key) {
            $item['url']       = esc_url_raw($url);
            $item['reason']    = sanitize_text_field($reason);
            $item['type']      = sanitize_key($type);
            $item['last_seen'] = $now;
            $item['attempts']  = max(1, intval($item['attempts'] ?? 0) + 1);
            $found = true;
            break;
        }
    }
    unset($item);

    if (!$found) {
        array_unshift($items, [
            'key'        => $key,
            'url'        => esc_url_raw($url),
            'reason'     => sanitize_text_field($reason),
            'type'       => sanitize_key($type),
            'first_seen' => $now,
            'last_seen'  => $now,
            'attempts'   => 1,
        ]);
    }

    ans_quality_hold_save(array_slice($items, 0, 500));
}

// CLEAN QUEUE
add_action('wp_ajax_ans_clean_queue', function() {
    ans_verify_request();
    $q      = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    $before = count($q);
    $q      = array_values(array_filter($q, function($u) { return (bool) ans_validate_scrape_url($u, false); }));
    update_option('ans_queue', $q);
    wp_send_json_success("Cleaned " . ($before - count($q)) . " unsafe URLs. Remaining: " . count($q));
});

// ============================================================
// AJAX HANDLERS — SCRAPER
// ============================================================
add_action('wp_ajax_ans_save', function() {
    ans_verify_request();
    $fields = ['lang' => 'ans_target_lang', 'status' => 'ans_post_status', 'img' => 'ans_import_img', 'sitemap' => 'ans_sitemap_url', 'title' => 'ans_title_sel', 'body' => 'ans_body_sel', 'manual_category' => 'ans_manual_category', 'my_brand' => 'ans_my_brand', 'delay' => 'ans_scrape_delay'];
    foreach ($fields as $post_key => $opt_key) {
        if (isset($_POST[$post_key])) update_option($opt_key, ans_sanitize_option_value($opt_key, $_POST[$post_key]));
    }
    wp_send_json_success();
});

add_action('wp_ajax_ans_count', function() {
    ans_verify_request();
    $q = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    wp_send_json_success(count($q));
});

add_action('wp_ajax_ans_clear', function() {
    ans_verify_request();
    update_option('ans_queue', []);
    wp_send_json_success();
});

add_action('wp_ajax_ans_save_queue', function() {
    ans_verify_request();
    $urls     = $_POST['urls'] ?? [];
    if (!is_array($urls)) $urls = [$urls];
    $filtered = [];
    foreach ($urls as $u) {
        $safe = ans_validate_scrape_url($u, false);
        if ($safe) $filtered[] = $safe;
    }
    $filtered = array_values(array_unique($filtered));
    $skipped = count($urls) - count($filtered);
    update_option('ans_queue', $filtered);
    $msg = "Queued " . count($filtered) . " URLs.";
    if ($skipped > 0) $msg .= " ($skipped unsafe URLs filtered)";
    wp_send_json_success($msg);
});

add_action('wp_ajax_ans_get_next_task', function() {
    ans_verify_request();
    $q = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    if (empty($q)) wp_send_json_error('Queue empty');
    wp_send_json_success($q[0]);
});

add_action('wp_ajax_ans_skip_url', function() {
    ans_verify_request();
    $q = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    array_shift($q);
    update_option('ans_queue', $q);
    wp_send_json_success();
});

add_action('wp_ajax_ans_retry_urls', function() {
    ans_verify_request();

    $urls = $_POST['urls'] ?? [];
    if (!is_array($urls)) $urls = [$urls];

    $retry_urls = [];
    $filtered   = 0;

    foreach ($urls as $url) {
        $url = ans_validate_scrape_url($url, false);
        if (!$url) {
            $filtered++;
            continue;
        }
        $retry_urls[] = $url;
    }

    $retry_urls = array_values(array_unique($retry_urls));
    if (empty($retry_urls)) {
        wp_send_json_error(['msg' => 'No retryable post URLs selected.', 'filtered' => $filtered]);
    }

    $q      = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    $merged = array_values(array_unique(array_merge($retry_urls, $q)));
    update_option('ans_queue', $merged);

    wp_send_json_success([
        'queued'   => count($retry_urls),
        'filtered' => $filtered,
        'total'    => count($merged),
    ]);
});

add_action('wp_ajax_ans_quality_hold_list', function() {
    ans_verify_request();
    $items = ans_quality_hold_items();
    wp_send_json_success(['items' => array_values($items), 'count' => count($items)]);
});

add_action('wp_ajax_ans_quality_hold_retry', function() {
    ans_verify_request();

    $all  = isset($_POST['all']) && wp_unslash($_POST['all']) == '1';
    $urls = $_POST['urls'] ?? [];
    if (!is_array($urls)) $urls = [$urls];

    $items = ans_quality_hold_items();
    $selected = [];
    if ($all) {
        foreach ($items as $item) {
            if (!empty($item['url'])) $selected[] = $item['url'];
        }
    } else {
        foreach ($urls as $url) {
            $safe = ans_validate_scrape_url($url, false);
            if ($safe) $selected[] = $safe;
        }
    }

    $selected = array_values(array_unique($selected));
    if (empty($selected)) wp_send_json_error('No review-later URLs selected.');

    $q = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    update_option('ans_queue', array_values(array_unique(array_merge($selected, $q))));

    $selected_keys = [];
    foreach ($selected as $url) $selected_keys[md5(strtolower(trim($url)))] = true;
    $remaining = [];
    foreach ($items as $item) {
        $key = !empty($item['key']) ? $item['key'] : (!empty($item['url']) ? md5(strtolower(trim($item['url']))) : '');
        if ($key === '' || isset($selected_keys[$key])) continue;
        $remaining[] = $item;
    }
    ans_quality_hold_save($remaining);

    wp_send_json_success(['queued' => count($selected), 'remaining' => count($remaining)]);
});

add_action('wp_ajax_ans_quality_hold_delete', function() {
    ans_verify_request();

    $all  = isset($_POST['all']) && wp_unslash($_POST['all']) == '1';
    $urls = $_POST['urls'] ?? [];
    if (!is_array($urls)) $urls = [$urls];

    if ($all) {
        ans_quality_hold_save([]);
        wp_send_json_success(['deleted' => 'all', 'remaining' => 0]);
    }

    $delete_keys = [];
    foreach ($urls as $url) {
        $safe = ans_validate_scrape_url($url, false);
        if ($safe) $delete_keys[md5(strtolower(trim($safe)))] = true;
    }
    if (empty($delete_keys)) wp_send_json_error('No review-later URLs selected.');

    $remaining = [];
    foreach (ans_quality_hold_items() as $item) {
        $key = !empty($item['key']) ? $item['key'] : (!empty($item['url']) ? md5(strtolower(trim($item['url']))) : '');
        if ($key !== '' && isset($delete_keys[$key])) continue;
        $remaining[] = $item;
    }
    ans_quality_hold_save($remaining);

    wp_send_json_success(['deleted' => count($delete_keys), 'remaining' => count($remaining)]);
});

// Queue preview
add_action('wp_ajax_ans_get_queue_preview', function() {
    ans_verify_request();
    $q = get_option('ans_queue', []);
    if (!is_array($q)) $q = [];
    $mc = count(array_filter($q, function($u) { return !ans_validate_scrape_url($u, false); }));
    wp_send_json_success(['has_media' => $mc > 0, 'media_count' => $mc]);
});

// ============================================================
// DUPLICATE CLEANER
// ============================================================
add_action('wp_ajax_ans_scan_duplicates', function() {
    ans_verify_request();
    global $wpdb;
    $results = $wpdb->get_results("SELECT post_title, GROUP_CONCAT(ID ORDER BY ID ASC) as ids, COUNT(*) as cnt FROM $wpdb->posts WHERE post_status='publish' AND post_type='post' GROUP BY post_title HAVING cnt > 1");
    $ids_to_delete = []; $preview = []; $total = 0;
    foreach ($results as $row) {
        $ids = explode(',', $row->ids);
        array_shift($ids); // keep oldest
        $ids_to_delete = array_merge($ids_to_delete, $ids);
        $total += count($ids);
        if (count($preview) < 20) $preview[] = ['title' => $row->post_title, 'count' => $row->cnt];
    }
    wp_send_json_success(['count' => count($results), 'ids_to_delete' => $ids_to_delete, 'preview' => $preview, 'total_dups' => $total]);
});

// BATCH DELETE — avoids timeout on 500+ posts
add_action('wp_ajax_ans_delete_selected', function() {
    ans_verify_request();
    $ids    = $_POST['ids'] ?? [];
    if (!is_array($ids)) $ids = [];
    $force  = isset($_POST['force']) && wp_unslash($_POST['force']) == '1'; // permanent delete
    $batch  = array_splice($ids, 0, 50); // process 50 at a time
    $count  = 0;
    foreach ($batch as $id) {
        $id = absint($id);
        if (!$id || !current_user_can('delete_post', $id)) continue;
        if ($force) wp_delete_post($id, true);  // permanent
        else        wp_trash_post($id);
        $count++;
    }
    // Return remaining IDs for next batch
    wp_send_json_success(['deleted' => $count, 'remaining' => $ids, 'msg' => "Deleted $count posts." . (empty($ids) ? " All done!" : " " . count($ids) . " remaining.")]);
});

// SINGLE DUPLICATE DELETE
add_action('wp_ajax_ans_delete_dup_single', function() {
    ans_verify_request();
    global $wpdb;
    $title = sanitize_text_field(wp_unslash($_POST['title'] ?? ''));
    if (empty($title)) wp_send_json_error('No title.');
    $ids = $wpdb->get_col($wpdb->prepare("SELECT ID FROM $wpdb->posts WHERE post_title=%s AND post_type='post' ORDER BY ID ASC", $title));
    if (count($ids) > 1) {
        array_shift($ids);
        $deleted = 0;
        foreach ($ids as $id) {
            $id = absint($id);
            if (!$id || !current_user_can('delete_post', $id)) continue;
            wp_trash_post($id);
            $deleted++;
        }
        wp_send_json_success("Deleted " . $deleted . " copies of '$title'.");
    } else {
        wp_send_json_error("No duplicates found.");
    }
});

// ============================================================
// CONTENT FETCHER
// ============================================================
function ans_fetch_content($url) {
    $reason = '';
    $url = ans_validate_scrape_url($url, true, $reason);
    if (!$url) return false;

    // Try Jina AI first
    $request_args = [
        'timeout' => 45,
        'redirection' => 3,
        'reject_unsafe_urls' => true,
        'limit_response_size' => 5242880,
        'headers' => ['X-Return-Format' => 'html'],
    ];
    $res = wp_safe_remote_get('https://r.jina.ai/' . $url, $request_args);
    if (!is_wp_error($res) && wp_remote_retrieve_response_code($res) == 200) {
        $body = wp_remote_retrieve_body($res);
        if (strlen($body) > 500) return $body;
    }
    // Try direct fetch
    $res2 = wp_safe_remote_get($url, [
        'timeout' => 45,
        'redirection' => 3,
        'reject_unsafe_urls' => true,
        'limit_response_size' => 5242880,
        'headers' => ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)', 'Referer' => 'https://www.google.com/'],
        'sslverify' => true,
    ]);
    if (!is_wp_error($res2) && wp_remote_retrieve_response_code($res2) == 200) {
        return wp_remote_retrieve_body($res2);
    }
    return false;
}

if (!function_exists('ans_is_blocked_or_challenge_html')) {
    function ans_is_blocked_or_challenge_html($html) {
        $text = strtolower(wp_strip_all_tags((string) $html));
        $raw  = strtolower((string) $html);

        $hard_markers = [
            'cf-browser-verification',
            'cf-chl',
            'challenge-platform',
            '__cf_chl_',
            '/cdn-cgi/challenge-platform',
            'ddos protection by cloudflare',
        ];
        foreach ($hard_markers as $marker) {
            if (strpos($raw, $marker) !== false) return true;
        }

        $soft_markers = [
            'just a moment',
            'checking your browser',
            'verify you are human',
            'enable javascript and cookies',
            'please enable cookies',
            'attention required',
            'access denied',
        ];
        foreach ($soft_markers as $marker) {
            if (strpos($text, $marker) !== false && strlen($text) < 3000) return true;
        }

        return false;
    }
}

// ============================================================
// CATEGORY EXTRACTION HELPERS
// ============================================================
if (!function_exists('ans_extract_meta_category')) {
    function ans_extract_meta_category($xpath) {
        $meta_queries = [
            "//meta[translate(@property, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='article:section']/@content",
            "//meta[translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='category']/@content",
            "//meta[translate(@property, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='category']/@content",
            "//meta[translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='parsely-section']/@content",
            "//meta[translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='sailthru.tags']/@content",
        ];

        foreach ($meta_queries as $query) {
            $nodes = $xpath->query($query);
            foreach ($nodes as $node) {
                $value = ans_clean_category_candidate($node->nodeValue);
                if ($value !== '') {
                    $parts = preg_split('/\s*,\s*/', $value);
                    foreach ($parts as $part) {
                        $candidate = ans_clean_category_candidate($part);
                        if ($candidate !== '') return $candidate;
                    }
                }
            }
        }

        return '';
    }
}

if (!function_exists('ans_clean_category_candidate')) {
    function ans_clean_category_candidate($text) {
        $text = html_entity_decode(wp_strip_all_tags((string) $text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace('/\s+/', ' ', trim($text));
        $text = trim($text, " \t\n\r\0\x0B|/-:,.");
        $text = preg_replace('/^(posted\s+in|filed\s+under|category|categories|in)\s*[:\-]?\s*/i', '', $text);
        $text = trim($text, " \t\n\r\0\x0B|/-:,.");

        if ($text === '' || strlen($text) > 80) return '';
        if (preg_match('/^(by|author|written by|reviewed by|updated|posted|comments?|leave a comment|read more)$/i', $text)) return '';
        if (preg_match('/\b(january|february|march|april|may|june|july|august|september|october|november|december)\b/i', $text)) return '';
        if (preg_match('/\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b/', $text)) return '';
        if (preg_match('/^\d+\s*(comments?|views?)$/i', $text)) return '';

        return sanitize_text_field($text);
    }
}

if (!function_exists('ans_normalize_url_category_segment')) {
    function ans_normalize_url_category_segment($segment) {
        $segment = rawurldecode((string) $segment);
        $segment = preg_replace('/\.(html?|php|aspx?)$/i', '', $segment);
        $segment = str_replace(['-', '_', '+'], ' ', $segment);
        $segment = preg_replace('/\s+/', ' ', trim($segment));

        if ($segment === '') return '';
        if (preg_match('/^(amp|feed|feeds|rss|print|page|pages|category|categories|tag|tags|author|authors)$/i', $segment)) return '';
        if (preg_match('/^\d+$/', $segment)) return '';

        return ans_clean_category_candidate(ucwords(strtolower($segment)));
    }
}

if (!function_exists('ans_extract_url_category_chain')) {
    function ans_extract_url_category_chain($url) {
        $path = wp_parse_url(trim((string) $url), PHP_URL_PATH);
        if (empty($path)) return [];

        $segments = array_values(array_filter(explode('/', trim($path, '/')), function($segment) {
            return trim($segment) !== '';
        }));

        // Last URL segment is treated as the article slug; folders before it are categories.
        if (count($segments) < 2) return [];

        $chain = [];
        foreach (array_slice($segments, 0, -1) as $segment) {
            $category = ans_normalize_url_category_segment($segment);
            if ($category === '') continue;

            $last = empty($chain) ? '' : end($chain);
            if ($last !== '' && strtolower($last) === strtolower($category)) continue;

            $chain[] = $category;
        }

        return $chain;
    }
}

if (!function_exists('ans_ensure_category_chain')) {
    function ans_ensure_category_chain($category_chain) {
        $ids       = [];
        $parent_id = 0;

        foreach ((array) $category_chain as $name) {
            $name = sanitize_text_field(wp_strip_all_tags((string) $name));
            $name = preg_replace('/\s+/', ' ', trim($name));
            if ($name === '') continue;

            $term    = term_exists($name, 'category', $parent_id);
            $term_id = 0;

            if ($term && !is_wp_error($term)) {
                $term_id = is_array($term) ? (int) $term['term_id'] : (int) $term;
            } else {
                $inserted = wp_insert_term($name, 'category', ['parent' => $parent_id]);
                if (!is_wp_error($inserted)) {
                    $term_id = (int) $inserted['term_id'];
                } else {
                    $existing_id = $inserted->get_error_data('term_exists');
                    if ($existing_id) $term_id = (int) $existing_id;
                }
            }

            if ($term_id > 0) {
                $ids[]     = $term_id;
                $parent_id = $term_id;
            }
        }

        return array_values(array_unique($ids));
    }
}

if (!function_exists('ans_find_date_span')) {
    function ans_find_date_span($text) {
        $months = 'january|jan\.?|february|feb\.?|march|mar\.?|april|apr\.?|may|june|jun\.?|july|jul\.?|august|aug\.?|september|sep\.?|sept\.?|october|oct\.?|november|nov\.?|december|dec\.?';
        $patterns = [
            '/\b(?:' . $months . ')\s+\d{1,2},?\s+\d{4}\b/i',
            '/\b\d{1,2}\s+(?:' . $months . '),?\s+\d{4}\b/i',
            '/\b\d{4}[\/\-.]\d{1,2}[\/\-.]\d{1,2}\b/',
            '/\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b/',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $text, $m, PREG_OFFSET_CAPTURE)) {
                return [$m[0][1], $m[0][1] + strlen($m[0][0])];
            }
        }
        return false;
    }
}

if (!function_exists('ans_is_author_or_meta_link')) {
    function ans_is_author_or_meta_link($node) {
        $text  = strtolower(trim(preg_replace('/\s+/', ' ', $node->textContent)));
        $href  = strtolower($node->getAttribute('href'));
        $rel   = strtolower($node->getAttribute('rel'));
        $class = strtolower($node->getAttribute('class'));

        if ($text === '') return true;
        if (strpos($rel, 'author') !== false) return true;
        if (preg_match('/(^|\s)(author|byline|url|fn|avatar)(\s|$)/', $class)) return true;
        if (preg_match('#/(author|about|team|user|profile)/#', $href)) return true;
        if (preg_match('/\b(author|writer|medical writer|nutritionist|reviewer|editor)\b/i', $text)) return true;
        if (preg_match('/^(facebook|twitter|pinterest|linkedin|email|print|share)$/i', $text)) return true;
        if (preg_match('/^(comments?|leave a comment|\d+\s*comments?)$/i', $text)) return true;

        return false;
    }
}

if (!function_exists('ans_extract_category_after_date')) {
    function ans_extract_category_after_date($xpath) {
        $meta_xpath = "//*[contains(@class, 'entry-meta') or contains(@class, 'post-meta') or contains(@class, 'postmeta') or contains(@class, 'article-meta') or contains(@class, 'meta-info') or contains(@class, 'date-cat') or contains(@class, 'post-info') or contains(@class, 'byline')]";
        $containers = $xpath->query($meta_xpath);
        if (!$containers || $containers->length === 0) {
            $containers = $xpath->query("//*[count(.//a) > 0 and string-length(normalize-space(.)) < 350]");
        }

        foreach ($containers as $container) {
            $line = preg_replace('/\s+/', ' ', trim($container->textContent));
            $date_span = ans_find_date_span($line);

            $time_nodes = $xpath->query(".//time|.//*[contains(concat(' ', normalize-space(@class), ' '), ' date ') or contains(concat(' ', normalize-space(@class), ' '), ' posted-on ') or contains(concat(' ', normalize-space(@class), ' '), ' meta_date ')]", $container);
            if (!$date_span && $time_nodes->length === 0) continue;
            $date_end = $date_span ? $date_span[1] : 0;

            $links = $xpath->query(".//a", $container);
            foreach ($links as $link) {
                if (ans_is_author_or_meta_link($link)) continue;

                $candidate = ans_clean_category_candidate($link->textContent);
                if ($candidate === '') continue;

                $pos = strpos($line, trim(preg_replace('/\s+/', ' ', $link->textContent)), $date_end);
                if ($pos !== false || $time_nodes->length > 0) return $candidate;
            }

            if ($date_span) {
                $after_date = substr($line, $date_span[1]);
                $parts = preg_split('/\s*(?:\||\/|,|-)\s*/', $after_date);
                foreach ($parts as $part) {
                    $candidate = ans_clean_category_candidate($part);
                    if ($candidate !== '') return $candidate;
                }
            }
        }

        return '';
    }
}

if (!function_exists('ans_normalize_junk_text')) {
    function ans_normalize_junk_text($text) {
        $decode_flags = ENT_QUOTES;
        if (defined('ENT_HTML5')) $decode_flags |= ENT_HTML5;
        $text = html_entity_decode(wp_strip_all_tags((string) $text), $decode_flags, 'UTF-8');
        $text = strtolower(trim($text));
        $text = preg_replace('/\x{00a0}/u', ' ', $text);
        $text = preg_replace('/[\x{00c4}\x{00e4}]/u', 'ae', $text);
        $text = preg_replace('/\s+/', ' ', $text);
        return trim($text);
    }
}

if (!function_exists('ans_is_article_nav_junk_text')) {
    function ans_is_article_nav_junk_text($text) {
        $text = ans_normalize_junk_text($text);
        if ($text === '') return false;

        $phrases = [
            'previous article',
            'next article',
            'previous post',
            'next post',
            'load more',
            'read more',
            'vorheriger artikel',
            'naechster artikel',
            'vorheriger beitrag',
            'naechster beitrag',
            'mehr laden',
        ];

        foreach ($phrases as $phrase) {
            if ($text === $phrase) return true;
        }

        if (strlen($text) > 220) return false;

        $remainder = $text;
        usort($phrases, function($a, $b) {
            return strlen($b) - strlen($a);
        });
        foreach ($phrases as $phrase) {
            $remainder = str_replace($phrase, ' ', $remainder);
        }
        $remainder = preg_replace('/[\s\|\-_:;,.\/<>]+/', ' ', $remainder);

        return trim($remainder) === '';
    }
}

if (!function_exists('ans_strip_article_nav_junk_html')) {
    function ans_strip_article_nav_junk_html($html) {
        $html = (string) $html;
        if (trim($html) === '') return $html;

        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $flags = 0;
        if (defined('LIBXML_HTML_NOIMPLIED')) $flags |= LIBXML_HTML_NOIMPLIED;
        if (defined('LIBXML_HTML_NODEFDTD')) $flags |= LIBXML_HTML_NODEFDTD;

        $loaded = @$dom->loadHTML('<?xml encoding="UTF-8"><div id="ans-clean-fragment">' . $html . '</div>', $flags);
        libxml_clear_errors();
        if (!$loaded) return $html;

        $xpath = new DOMXPath($dom);
        $wrap  = $dom->getElementById('ans-clean-fragment');
        if (!$wrap) return $html;

        $to_kill = [];
        foreach ($xpath->query(".//*", $wrap) as $node) {
            if (!$node->parentNode) continue;
            if (ans_is_article_nav_junk_text($node->textContent)) $to_kill[] = $node;
        }
        foreach (array_reverse($to_kill) as $node) {
            if ($node->parentNode) $node->parentNode->removeChild($node);
        }

        foreach ($xpath->query(".//text()", $wrap) as $node) {
            if ($node->parentNode && ans_is_article_nav_junk_text($node->nodeValue)) {
                $node->parentNode->removeChild($node);
            }
        }

        $clean = '';
        foreach ($wrap->childNodes as $child) {
            $clean .= $dom->saveHTML($child);
        }

        return $clean;
    }
}

if (!function_exists('ans_content_marker_text')) {
    function ans_content_marker_text($text) {
        $text = ans_normalize_junk_text($text);
        $text = preg_replace('/^[\s\-\|\:\.]+|[\s\-\|\:\.]+$/', '', $text);
        return trim($text);
    }
}

if (!function_exists('ans_is_related_articles_marker')) {
    function ans_is_related_articles_marker($text) {
        $text = ans_content_marker_text($text);
        return (bool) preg_match('/^((read|see|check)\s+(my|our|the)?\s*(other\s+)?related\s+(articles?|posts?)|related\s+(articles?|posts?)|other\s+related\s+(articles?|posts?)|verwandte\s+artikel|weitere\s+artikel|ahnliche\s+artikel|articulos\s+relacionados|articles\s+connexes|articles\s+lies|articoli\s+correlati|artigos\s+relacionados)\b/u', $text);
    }
}

if (!function_exists('ans_is_article_resource_marker')) {
    function ans_is_article_resource_marker($text) {
        $text = ans_content_marker_text($text);
        if ($text === '') return false;

        $words = preg_split('/\s+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $word_count = is_array($words) ? count($words) : 0;

        // Only treat short heading-like labels as the source/reference cutoff.
        // Phrases like "Further reading: Read my article..." are part of the article body.
        if ($word_count > 5 || strlen($text) > 90) return false;

        return (bool) preg_match('/^((article|post|content)\s+)?(resources?|references?|sources?|citations?)\b|^(bibliography|works?\s+cited|quellen|artikelquellen|fuentes|referencias|sources\s+de|fonti|referenze)\b/u', $text);
    }
}

if (!function_exists('ans_is_related_item_block')) {
    function ans_is_related_item_block($node) {
        if (!$node || $node->nodeType !== XML_ELEMENT_NODE) return false;
        $tag = strtolower($node->nodeName);
        $text = ans_content_marker_text($node->textContent);
        if ($text === '') return false;
        if (in_array($tag, ['ul','ol'], true)) return true;
        if (preg_match('/^\d+[\.\)]\s+\S+/u', $text)) return true;
        $words = preg_split('/\s+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $word_count = is_array($words) ? count($words) : 0;
        if (in_array($tag, ['p','div','li'], true) && strlen($text) < 220 && $word_count >= 3 && $word_count <= 20) return true;
        if ($tag === 'p' && strlen($text) < 180 && preg_match('/\b(cancer|symptoms|warning|signs|reasons|ignore|articles?)\b/u', $text)) return true;
        return false;
    }
}

if (!function_exists('ans_node_word_count')) {
    function ans_node_word_count($node) {
        $text = $node ? ans_content_marker_text($node->textContent) : '';
        if ($text === '') return 0;
        if (preg_match_all('/[\p{L}\p{N}]+/u', $text, $matches)) return count($matches[0]);
        return str_word_count($text);
    }
}

if (!function_exists('ans_node_has_junk_context')) {
    function ans_node_has_junk_context($node) {
        if (!$node || $node->nodeType !== XML_ELEMENT_NODE) return false;
        $context = strtolower(trim($node->getAttribute('class') . ' ' . $node->getAttribute('id')));
        if ($context === '') return false;

        return (bool) preg_match('/(?:^|[\s_-])(related|recommended|popular|trending|share|social|author|comments?|breadcrumb|nav|navigation|meta|categor(?:y|ies)|tags?|footer|sidebar|widget|advertisement|advert|ads)(?:$|[\s_-])/i', $context);
    }
}

if (!function_exists('ans_is_substantial_article_body_block')) {
    function ans_is_substantial_article_body_block($node) {
        if (!$node || $node->nodeType !== XML_ELEMENT_NODE) return false;
        if (ans_node_has_junk_context($node)) return false;

        $tag  = strtolower($node->nodeName);
        $text = ans_content_marker_text($node->textContent);
        if ($text === '') return false;
        if (ans_is_article_nav_junk_text($text) || ans_is_article_resource_marker($text) || ans_is_related_articles_marker($text)) return false;

        $word_count = ans_node_word_count($node);
        $char_count = function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : strlen($text);

        if (in_array($tag, ['p','blockquote'], true)) {
            return $word_count >= 6 && $char_count >= 35;
        }

        if (in_array($tag, ['ul','ol'], true)) {
            if ($word_count >= 40) return true;
            foreach ($node->getElementsByTagName('li') as $li) {
                if (ans_node_word_count($li) >= 12) return true;
            }
            return false;
        }

        if (in_array($tag, ['div','section','article'], true)) {
            foreach (['p','blockquote','ul','ol'] as $child_tag) {
                foreach ($node->getElementsByTagName($child_tag) as $child) {
                    if (ans_is_substantial_article_body_block($child)) return true;
                }
            }
        }

        return false;
    }
}

if (!function_exists('ans_content_block_node')) {
    function ans_content_block_node($node, $target) {
        $block_tags = ['p','div','section','article','h2','h3','h4','h5','h6','ul','ol','li'];
        while ($node && $node->parentNode && $node->parentNode !== $target) {
            if ($node->nodeType === XML_ELEMENT_NODE && in_array(strtolower($node->nodeName), $block_tags, true)) {
                return $node;
            }
            $node = $node->parentNode;
        }
        return $node ?: null;
    }
}

if (!function_exists('ans_next_element_sibling')) {
    function ans_next_element_sibling($node) {
        $node = $node ? $node->nextSibling : null;
        while ($node && $node->nodeType !== XML_ELEMENT_NODE) {
            $node = $node->nextSibling;
        }
        return $node;
    }
}

if (!function_exists('ans_has_substantial_body_after_node')) {
    function ans_has_substantial_body_after_node($node, $target) {
        if (!$node || !$target) return false;

        $cursor = $node;
        while ($cursor && $cursor !== $target) {
            $next = ans_next_element_sibling($cursor);
            $scanned = 0;

            while ($next && $scanned < 40) {
                if (ans_is_substantial_article_body_block($next)) return true;
                $next = ans_next_element_sibling($next);
                $scanned++;
            }

            $cursor = $cursor->parentNode;
        }

        return false;
    }
}

if (!function_exists('ans_remove_following_siblings')) {
    function ans_remove_following_siblings($node) {
        $next = $node ? $node->nextSibling : null;
        while ($next) {
            $current = $next;
            $next = $next->nextSibling;
            if ($current->parentNode) $current->parentNode->removeChild($current);
        }
    }
}

if (!function_exists('ans_trim_article_tail_after_node')) {
    function ans_trim_article_tail_after_node($node, $target) {
        if (!$node) return;
        ans_remove_following_siblings($node);

        $ancestor = $node->parentNode;
        while ($ancestor && $ancestor !== $target) {
            ans_remove_following_siblings($ancestor);
            $ancestor = $ancestor->parentNode;
        }
    }
}

if (!function_exists('ans_trim_content_tail')) {
    function ans_trim_content_tail($target, $xpath) {
        if (!$target || !$xpath) return;

        $related_nodes = [];
        foreach ($xpath->query(".//*", $target) as $node) {
            if (!$node->parentNode) continue;
            if (ans_is_related_articles_marker($node->textContent)) {
                $candidate = ans_content_block_node($node, $target);
                if ($candidate) {
                    $hash = spl_object_hash($candidate);
                    $related_nodes[$hash] = $candidate;
                }
            }
        }

        foreach ($related_nodes as $related_node) {
            foreach ($xpath->query(".//*", $related_node) as $node) {
                if (!$node->parentNode || $node === $related_node) continue;
                if (ans_is_article_resource_marker($node->textContent)) {
                    $resource_node = ans_content_block_node($node, $related_node);
                    if ($resource_node && $resource_node->parentNode) {
                        ans_trim_article_tail_after_node($resource_node, $related_node);
                        $resource_node->parentNode->removeChild($resource_node);
                    }
                    break;
                }
            }

            $last_keep = $related_node;
            $next = ans_next_element_sibling($last_keep);
            $kept = 0;
            while ($next && $kept < 8) {
                if (ans_is_article_resource_marker($next->textContent) || ans_is_article_nav_junk_text($next->textContent)) break;
                if (!ans_is_related_item_block($next)) break;
                $last_keep = $next;
                $next = ans_next_element_sibling($last_keep);
                $kept++;
            }

            if (ans_has_substantial_body_after_node($last_keep, $target)) continue;

            ans_trim_article_tail_after_node($last_keep, $target);
            return;
        }

        $resource_node = null;
        $resource_score = PHP_INT_MAX;
        foreach ($xpath->query(".//*", $target) as $node) {
            if (!$node->parentNode) continue;
            if (ans_is_article_resource_marker($node->textContent)) {
                $candidate = ans_content_block_node($node, $target);
                $score = strlen(ans_content_marker_text($node->textContent));
                if ($candidate && $score < $resource_score) {
                    $resource_node = $candidate;
                    $resource_score = $score;
                }
            }
        }
        if ($resource_node && $resource_node->parentNode) {
            ans_trim_article_tail_after_node($resource_node, $target);
            $resource_node->parentNode->removeChild($resource_node);
        }
    }
}

if (!function_exists('ans_dom_replace_tag')) {
    function ans_dom_replace_tag($dom, $node, $new_tag) {
        if (!$dom || !$node || !$node->parentNode) return null;

        $replacement = $dom->createElement($new_tag);
        while ($node->firstChild) {
            $replacement->appendChild($node->firstChild);
        }

        $node->parentNode->replaceChild($replacement, $node);
        return $replacement;
    }
}

if (!function_exists('ans_heading_should_be_paragraph')) {
    function ans_heading_should_be_paragraph($text) {
        $text = html_entity_decode(wp_strip_all_tags((string)$text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace('/\s+/u', ' ', trim($text));
        if ($text === '') return true;

        $words = preg_split('/\s+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $word_count = is_array($words) ? count($words) : 0;
        $char_count = function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : strlen($text);

        if ($word_count >= 16) return true;
        if ($char_count > 105) return true;
        if ($word_count >= 10 && preg_match('/[\.:\;]\s*$/u', $text)) return true;
        if ($word_count >= 10 && preg_match('/[\.:\;]\s+/u', $text)) return true;

        return false;
    }
}

if (!function_exists('ans_normalize_source_formatting')) {
    function ans_normalize_source_formatting($target, $dom) {
        if (!$target || !$dom) return;

        foreach (iterator_to_array($target->getElementsByTagName('*')) as $node) {
            if (!$node->hasAttributes()) continue;

            if (strtolower($node->nodeName) !== 'table') {
                $node->removeAttribute('style');
            }
            $node->removeAttribute('class');
            $node->removeAttribute('id');
            $node->removeAttribute('width');
            $node->removeAttribute('height');
            $node->removeAttribute('align');
        }

        foreach (['h2','h3','h4','h5','h6'] as $tag) {
            foreach (iterator_to_array($target->getElementsByTagName($tag)) as $heading) {
                if (ans_heading_should_be_paragraph($heading->textContent)) {
                    ans_dom_replace_tag($dom, $heading, 'p');
                }
            }
        }
    }
}

if (!function_exists('ans_html_word_count')) {
    function ans_html_word_count($html) {
        $text = html_entity_decode(wp_strip_all_tags((string) $html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace('/\s+/u', ' ', trim($text));
        if ($text === '') return 0;

        if (preg_match_all('/[\p{L}\p{N}]+/u', $text, $matches)) {
            return count($matches[0]);
        }

        return str_word_count($text);
    }
}

if (!function_exists('ans_content_structure_snapshot')) {
    function ans_content_structure_snapshot($html) {
        $html = (string) $html;
        $snapshot = [
            'sequence' => [],
            'counts'   => [],
        ];

        if (trim($html) === '') return $snapshot;

        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $flags = 0;
        if (defined('LIBXML_HTML_NOIMPLIED')) $flags |= LIBXML_HTML_NOIMPLIED;
        if (defined('LIBXML_HTML_NODEFDTD')) $flags |= LIBXML_HTML_NODEFDTD;
        $loaded = @$dom->loadHTML('<?xml encoding="UTF-8"><div id="ans-structure-fragment">' . $html . '</div>', $flags);
        libxml_clear_errors();
        if (!$loaded) return $snapshot;

        $xpath = new DOMXPath($dom);
        $wrap  = $dom->getElementById('ans-structure-fragment');
        if (!$wrap) return $snapshot;

        $query = ".//*[self::p or self::h2 or self::h3 or self::h4 or self::h5 or self::h6 or self::blockquote or self::li or self::table or self::img]";
        foreach ($xpath->query($query, $wrap) as $node) {
            $tag = strtolower($node->nodeName);
            if ($tag !== 'img') {
                $text = ans_content_marker_text($node->textContent);
                if ($text === '') continue;
            }

            $snapshot['sequence'][] = $tag;
            $snapshot['counts'][$tag] = isset($snapshot['counts'][$tag]) ? $snapshot['counts'][$tag] + 1 : 1;
        }

        return $snapshot;
    }
}

if (!function_exists('ans_content_structure_mismatch_reason')) {
    function ans_content_structure_mismatch_reason($source, $final) {
        $source_sequence = isset($source['sequence']) && is_array($source['sequence']) ? $source['sequence'] : [];
        $final_sequence  = isset($final['sequence']) && is_array($final['sequence']) ? $final['sequence'] : [];

        if ($source_sequence === $final_sequence) return '';

        $source_counts = isset($source['counts']) && is_array($source['counts']) ? $source['counts'] : [];
        $final_counts  = isset($final['counts']) && is_array($final['counts']) ? $final['counts'] : [];
        $tags = array_unique(array_merge(array_keys($source_counts), array_keys($final_counts)));
        sort($tags);

        $diffs = [];
        foreach ($tags as $tag) {
            $a = isset($source_counts[$tag]) ? (int) $source_counts[$tag] : 0;
            $b = isset($final_counts[$tag]) ? (int) $final_counts[$tag] : 0;
            if ($a !== $b) $diffs[] = "$tag $a->$b";
        }

        if (!empty($diffs)) {
            return 'structure changed: ' . implode(', ', $diffs);
        }

        return 'block order changed';
    }
}

// ============================================================
// MAIN PROCESS CONTENT
// ============================================================
add_action('wp_ajax_ans_process_content', function() {
    ans_verify_request();
    if (!current_user_can('edit_posts')) wp_send_json_error('Permission denied.', 403);
    @ini_set('max_execution_time', 300);

    $reason = '';
    $url = ans_validate_scrape_url($_POST['url'] ?? '', true, $reason);
    if (!$url) {
        wp_send_json_error('Invalid or unsafe URL. ' . $reason);
        return;
    }

    // PHP GATE: Block media URLs
    if (ans_is_media_url($url) || strpos($url, '/wp-content/uploads/') !== false) {
        ans_queue_remove_current($url);
        wp_send_json_error("Skipped (Media URL)");
        return;
    }

    // DUPLICATE LOCK — prevent double processing
    $lock_key = 'ans_lock_' . md5($url);
    if (get_transient($lock_key)) {
        wp_send_json_error("Already processing. Wait...");
        return;
    }
    set_transient($lock_key, true, 300);

    // DUPLICATE URL CHECK — already in DB?
    global $wpdb;
    $existing_src_post_id = 0;
    $clean_url = trim(preg_replace('#^https?://#', '', $url), '/');
    $existing  = $wpdb->get_var($wpdb->prepare(
        "SELECT pm.post_id FROM $wpdb->postmeta pm INNER JOIN $wpdb->posts p ON p.ID=pm.post_id WHERE pm.meta_key='ans_src' AND p.post_status<>'trash' AND (pm.meta_value=%s OR pm.meta_value LIKE %s) LIMIT 1",
        $url, '%' . $wpdb->esc_like($clean_url) . '%'
    ));
    if ($existing) {
        $existing_src_post_id = (int) $existing;
    }

    $raw_html = ans_fetch_content($url);
    if (!$raw_html || strlen($raw_html) < 200) {
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Fetch Failed: " . esc_url($url));
        return;
    }

    if (ans_is_blocked_or_challenge_html($raw_html)) {
        // Anti-bot/challenge pages look parseable, but they are not articles.
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Blocked/Challenge page detected: " . esc_url($url));
        return;
    }

    $lang        = ans_sanitize_option_value('ans_target_lang', $_POST['lang'] ?? get_option('ans_target_lang'));
    $manual_cat  = ans_sanitize_option_value('ans_manual_category', get_option('ans_manual_category', ''));
    $body_sel    = ans_sanitize_option_value('ans_body_sel', $_POST['body_sel'] ?? get_option('ans_body_sel'));
    $title_sel   = ans_sanitize_option_value('ans_title_sel', $_POST['title_sel'] ?? get_option('ans_title_sel'));
    $img_opt     = ans_sanitize_option_value('ans_import_img', $_POST['img_opt'] ?? get_option('ans_import_img', 'no'));
    $post_status = ans_sanitize_option_value('ans_post_status', $_POST['status'] ?? get_option('ans_post_status', 'publish'));
    $my_brand    = ans_sanitize_option_value('ans_my_brand', get_option('ans_my_brand')) ?: get_bloginfo('name') ?: 'My Brand';

    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    @$dom->loadHTML('<?xml encoding="UTF-8">' . $raw_html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    $xpath = new DOMXPath($dom);

    // TITLE EXTRACTION
    $title = '';
    $page_title = '';
    $title_nodes = $xpath->query('//title');
    if ($title_nodes->length > 0) {
        $raw_t = trim($title_nodes->item(0)->textContent);
        $host  = wp_parse_url($url, PHP_URL_HOST);
        $parts = explode('.', $host);
        $site  = ($parts[0] === 'www') ? ($parts[1] ?? '') : ($parts[0] ?? '');
        $page_title = $site ? preg_replace('/(\s*[-|:]\s*' . preg_quote($site, '/') . '.*)$/i', '', $raw_t) : $raw_t;
    }
    if (!empty($title_sel)) {
        $title_xpath = ans_selector_to_xpath($title_sel);
        $n = $title_xpath ? $xpath->query($title_xpath) : null;
        if (!empty($n) && $n->length > 0) $title = trim($n->item(0)->textContent);
    }
    if (empty($title)) { $n = $xpath->query('//h1'); if ($n->length > 0) $title = trim($n->item(0)->textContent); }
    if (empty($title)) $title = $page_title;
    if (preg_match('/^(just a moment|one moment please|attention required|access denied)/i', trim($title))) {
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Blocked/Challenge title detected: " . esc_url($url));
        return;
    }

    // CATEGORY
    $category_chain = [];
    $manual_cat     = ans_clean_category_candidate($manual_cat);

    if (!empty($manual_cat)) {
        $category_chain = [$manual_cat];
    }
    if (empty($category_chain) && preg_match('/(^|\.)epainassist\.com$/i', (string) wp_parse_url($url, PHP_URL_HOST))) {
        // E Pain Assist keeps the category hierarchy in URL folders:
        // /pelvic-pain/uterus/article-slug => Pelvic Pain > Uterus, assign post to Uterus.
        $category_chain = ans_extract_url_category_chain($url);
    }
    if (empty($category_chain)) {
        // Prefer visible post-meta patterns from the source page:
        // Example: "May 30, 2016 | Health" => "Health"
        $category_name = ans_extract_category_after_date($xpath);
        if (!empty($category_name)) $category_chain = [$category_name];
    }
    if (empty($category_chain)) {
        // OpenGraph/SEO metadata often has the exact source category.
        // Example: <meta property="article:section" content="Health">
        $category_name = ans_extract_meta_category($xpath);
        if (!empty($category_name)) $category_chain = [$category_name];
    }
    if (empty($category_chain)) {
        $bread = $xpath->query("//*[contains(@class,'yoast-breadcrumbs') or contains(@class,'breadcrumb') or contains(@class,'breadcrumbs')]//a");
        if ($bread->length >= 2) $category_chain = [ans_clean_category_candidate($bread->item(1)->textContent)];
        elseif ($bread->length == 1) $category_chain = [ans_clean_category_candidate($bread->item(0)->textContent)];
        $category_chain = array_values(array_filter($category_chain));

        if (empty($category_chain)) {
            $meta = $xpath->query("//*[contains(@class,'cat-links') or contains(@class,'meta_categories') or contains(@class,'category-links') or contains(@class,'post-categories')]//a");
            foreach ($meta as $m) {
                if (ans_is_author_or_meta_link($m)) continue;
                $category_name = ans_clean_category_candidate($m->textContent);
                if (!empty($category_name)) {
                    $category_chain = [$category_name];
                    break;
                }
            }
        }
    }
    if (empty($category_chain)) {
        // Keep URL-folder category logic exactly as fallback for sites where category lives in the path:
        // /pelvic-pain/uterus/tubal-disease => Pelvic Pain > Uterus
        // /mental-health/hallucinations => Mental Health
        $category_chain = ans_extract_url_category_chain($url);
    }
    if (empty($category_chain)) $category_chain = ['Uncategorized'];
    $category_name = end($category_chain);

    // DOM SHREDDER
    foreach (['header','footer','nav','aside','form','button','script','style','noscript','link','meta','object','embed','iframe','svg'] as $tag) {
        $nodes = $dom->getElementsByTagName($tag);
        $arr = [];
        foreach ($nodes as $n) $arr[] = $n;
        foreach ($arr as $n) if ($n->parentNode) $n->parentNode->removeChild($n);
    }

    // BODY TARGET — improved fallback chain
    $target = null;
    if (!empty($body_sel)) {
        $body_xpath = ans_selector_to_xpath($body_sel);
        $n = $body_xpath ? $xpath->query($body_xpath) : null;
        if (!empty($n) && $n->length > 0) $target = $n->item(0);
    }
    // Improved fallback chain
    if (!$target) {
        $fallbacks = [
            "//article",
            "//*[not(self::meta) and @itemprop='articleBody']",
            "//div[contains(concat(' ', normalize-space(@class), ' '), ' entry ')]",
            "//div[contains(@class,'post-single')]",
            "//div[contains(@class,'entry-content')]",
            "//div[contains(@class,'article-content')]",
            "//div[contains(@class,'article-body')]",
            "//div[contains(@class,'post-content')]",
            "//div[contains(@class,'post-body')]",
            "//div[contains(@class,'content-body')]",
            "//div[contains(@class,'main-content')]",
            "//div[@id='content']",
            "//main",
            "//body"
        ];
        foreach ($fallbacks as $fb) {
            $n = $xpath->query($fb);
            if ($n->length > 0) { $target = $n->item(0); break; }
        }
    }

    if (!$target) {
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Content Extraction Failed: " . esc_url($url));
        return;
    }

    // CLEAN TARGET
    $h1s = $target->getElementsByTagName('h1');
    while ($h1s->length > 0) $h1s->item(0)->parentNode->removeChild($h1s->item(0));

    $titles_el = $xpath->query(".//*[contains(@class,'title') or contains(@class,'entry-title')]", $target);
    foreach ($titles_el as $te) if ($te->parentNode) $te->parentNode->removeChild($te);

    $links = $target->getElementsByTagName('a');
    while ($links->length > 0) {
        $link = $links->item(0);
        $tn   = $dom->createTextNode($link->textContent);
        if ($link->parentNode) $link->parentNode->replaceChild($tn, $link);
        else break;
    }

    // JUNK CLASS REMOVAL
    $junk = ['medical-review-disclaimer','collapsible-content-section','headline-with-intro','inline-cta-panel','callout','billboard-ad','native-ad-desktop','native-ad-mobile','leaderboard-ad','adhesive-ad','article-navigation','article-nav','post-navigation','post-nav','nav-links','pagination','pager','load-more','loadmore','ajax-load-more','prev-next','next-prev','breadcrumbs','entry-meta','disclaimer-top','hg-rp','abox','autor','hausg-taboola','overline','subscription-card','social-share-links','category-spotlight-panel','trending-topics-panel','single-line-nav','site-header-navigation-links','utility-navigation','footer-nav','copyright-footer','social-footer','author-box','author-bio','user-profile','site-header','site-footer','main-nav','top-nav','breadcrumb','toc_container','lwptoc','ez-toc-container','toc-wrapper','algolia-search-box','utility-bar','scriptlesssocialsharing','postmeta-primary','postmeta','meta_date','meta_categories','hatom-extra','share-buttons','share-links','social-share','social-links','ad-container','advertisement','adsbygoogle','g-single','g-col','ads','legal-warning','disclaimer','instaread-player','about-author','post-author','author-info','post-meta','post-time','reading-time','meta-info','article-meta','date-cat','date-single','social-buttons-top','social-buttons-bottom','social-wrap','sidebar','sidebar-team','sidebar-logos','see-all','cnt-summary','docti__voir-aussi','docti__related-diaporama','docti__m-source-article','docti__share-article','docti__post-crd','docti__top-article','docti__redacteur','post-modified-info','last-updated-info','updated-date',
        // Share box patterns
        'share-story','share-this','sharethis','social-sharing','share-box','share-widget','share-article','share-post','share-section','story-share','article-share','post-share','share-container','sharing-buttons','share-icons','share-panel','addtoany','addthis','sharedaddy',
        // TOC / Content box patterns
        'table-of-contents','article-toc','post-toc','toc-box','toc-block','toc-section','contents-box','in-this-article','jump-links','article-contents','page-contents','content-nav','content-navigation','article-outline','topic-nav','on-this-page',
        // Clinical trial / CTA widgets
        'clinical-trial','eligibility-widget','cta-widget','cta-sidebar','cta-box','cta-panel','trial-widget','signup-widget','lead-widget','conversion-box','promotional-widget','sponsored-content','partner-content','native-content'];
    foreach ($junk as $j) {
        $nodes = $xpath->query(".//*[contains(@class,'$j') or @id='$j']", $target);
        foreach ($nodes as $n) if ($n->parentNode) $n->parentNode->removeChild($n);
    }

    // ============================================================
    // TOC KILLER — position-based: TOC is always among the FIRST elements
    // Only check first 3 direct children of $target for TOC pattern
    // ============================================================
    $direct_children = [];
    foreach ($target->childNodes as $child) {
        if ($child->nodeType === XML_ELEMENT_NODE) $direct_children[] = $child;
    }
    // Check only first 5 direct children
    $check_count = min(5, count($direct_children));
    for ($ci = 0; $ci < $check_count; $ci++) {
        $child = $direct_children[$ci];
        // Look for ul/ol anywhere inside this early child
        $lists = $child->getElementsByTagName('ul');
        if ($lists->length === 0) $lists = $child->getElementsByTagName('ol');
        foreach ($lists as $lst) {
            $lis = $lst->getElementsByTagName('li');
            $li_count = $lis->length;
            if ($li_count < 3) continue;
            $total_words = 0;
            $has_links   = 0;
            foreach ($lis as $li) {
                $total_words += str_word_count(trim($li->textContent));
                if ($li->getElementsByTagName('a')->length > 0) $has_links++;
            }
            $avg = $total_words / $li_count;
            // TOC: short items (avg < 8 words) AND most items are links (navigation)
            // OR: short items with no links but clearly just section names
            $link_ratio = $has_links / $li_count;
            if ($avg < 9 && ($link_ratio > 0.5 || $li_count >= 4)) {
                // Remove just the list and its immediate wrapper if wrapper has nothing else
                $lst_parent = $lst->parentNode;
                if ($lst->parentNode) $lst->parentNode->removeChild($lst);
                // If parent is now empty or just has a short heading, remove it too
                if ($lst_parent && strlen(trim($lst_parent->textContent)) < 100) {
                    if ($lst_parent->parentNode) $lst_parent->parentNode->removeChild($lst_parent);
                }
                break;
            }
        }
    }

    // ============================================================
    // DEEP CONTENT KILLER — runs on every node in the target
    // Kills: Share boxes, TOC, Clinical trial widgets, Author boxes
    // Works by TEXT CONTENT — not by class (classes are dynamic)
    // ============================================================
    function ans_node_should_die($node, $dom) {
        $txt = strtolower(trim($node->textContent));
        if (strlen($txt) === 0) return true; // empty
        if (ans_is_article_nav_junk_text($txt)) return true;

        // --- SHARE BOX --- (any lang: condividi, partager, teilen, compartir)
        $share_triggers = ['share this story','share this article','share this post',
            'condividi questa storia','condividi questo articolo','partager cet article',
            'teilen','compartir','share on facebook','share on twitter',
            'facebook','twitter','linkedin']; // only kill small containers with these
        $is_only_social = false;
        if (strlen($txt) < 200) {
            foreach ($share_triggers as $st) {
                if (strpos($txt, $st) !== false) { $is_only_social = true; break; }
            }
        }
        if ($is_only_social) return true;

        // --- TOC / CONTENT BOX ---
        // TOC appears ONLY at the very start of article content, never in the middle.
        // We do NOT use ans_node_should_die() for TOC — handled separately below.
        // (no code here — TOC handled after this loop)

        // --- CLINICAL TRIAL / CTA WIDGET ---
        $cta_phrases = ['check your eligibility','have you considered clinical',
            'we make it easy for you to participate','clinical trial for',
            'access to the latest treatments','not yet widely available',
            'be a part of finding a cure','discover your eligibility',
            'eligibilit','join a trial','participate in a clinical'];
        if (strlen($txt) < 1200) {
            foreach ($cta_phrases as $cp) {
                if (strpos($txt, $cp) !== false) return true;
            }
        }

        // --- AUTHOR / META blocks at end ---
        $meta_phrases = ['medically reviewed by','written by','fact-checked by',
            'reviewed by','updated at','last updated','min read',
            'add social links','edit profile','revisato da','scritto da',
            'aggiornato il','redatto da'];
        if (strlen($txt) < 400) {
            foreach ($meta_phrases as $mp) {
                if (strpos($txt, $mp) !== false) return true;
            }
        }

        return false;
    }

    // Walk all direct children and grandchildren of $target and remove junk
    $all_nodes = $xpath->query(".//*", $target);
    $to_kill = [];
    foreach ($all_nodes as $node) {
        if (!$node->parentNode) continue;
        if (ans_node_should_die($node, $dom)) {
            $to_kill[] = $node;
        }
    }
    // Kill deepest nodes first (reverse DOM order) to avoid parent-already-removed errors
    foreach (array_reverse($to_kill) as $kill) {
        if ($kill->parentNode) $kill->parentNode->removeChild($kill);
    }

    // Treat a source "Related articles" list as the article ending.
    // Remove source Resources/References and everything after the related list.
    ans_trim_content_tail($target, $xpath);

    // Normalize copied source formatting before WordPress/theme CSS takes over.
    // This prevents long body paragraphs from being imported as oversized headings.
    ans_normalize_source_formatting($target, $dom);

    // EMPTY DIV CLEANUP
    $divs = $target->getElementsByTagName('div');
    $empty_divs = [];
    foreach ($divs as $d) if (trim($d->textContent) == '') $empty_divs[] = $d;
    foreach ($empty_divs as $d) if ($d->parentNode) $d->parentNode->removeChild($d);

    // TABLE STYLING
    foreach ($target->getElementsByTagName('table') as $tbl) {
        $tbl->setAttribute('border', '1');
        $tbl->setAttribute('style', 'border-collapse:collapse;width:100%;border:1px solid #000;margin-bottom:20px;');
    }

    // BUILD CLEAN HTML
    $clean_html = '';
    if ($target->hasChildNodes()) {
        foreach ($target->childNodes as $child) $clean_html .= $dom->saveHTML($child);
    }
    if (strlen(trim($clean_html)) < 50) $clean_html = $dom->saveHTML($target);

    // REGEX CLEANUPS
    $clean_html = ans_strip_article_nav_junk_html($clean_html);
    $clean_html = preg_replace('/(\r\n|\r|\n)+/', ' ', $clean_html);
    $clean_html = preg_replace('/(Image content|Bild Inhalt|View image|This image is available).*?(\.|online)\.?/i', '', $clean_html);
    $clean_html = preg_replace('/Rendered:\s*.*GMT\+0000[^\n<]*/i', '', $clean_html);
    $clean_html = preg_replace('/\(https?:\/\/[^\s<>]+?\)/i', '', $clean_html);

    // BRAND REPLACEMENT - Placeholder trick taaki Google Translate brand ko translate na kare
    $brand_placeholder = 'MYBRANDTOKEN';
    $host        = wp_parse_url($url, PHP_URL_HOST);
    $base_domain = preg_replace('/^www\.|^m\./', '', $host);

    // Source site se brand text dynamically extract karo
    // e.g. "onsalus.com" => ONsalus, Onsalus, onsalus, ONSALUS
    $domain_parts  = explode('.', $base_domain);
    $site_word     = $domain_parts[0];                                       // "onsalus"
    $site_word_cap = ucfirst($site_word);                                    // "Onsalus"
    $site_word_uc  = strtoupper(substr($site_word, 0, 2)) . substr($site_word, 2); // "ONsalus"

    $source_brand_variants = array_unique([
        $base_domain,
        $host,
        $site_word_uc,
        $site_word_cap,
        $site_word,
        strtoupper($site_word),
        'Cleveland Clinic', 'Swip Health', 'Hausgarten.net', 'Hausgarten', 'Worst Room',
    ]);

    $clean_html = str_ireplace($source_brand_variants, $brand_placeholder, $clean_html);

    // IMAGE HANDLING
    if ($img_opt === 'no') {
        $clean_html = preg_replace('/<img[^>]+>/i', '', $clean_html);
        $clean_html = preg_replace('/<picture[^>]*>.*?<\/picture>/is', '', $clean_html);
        $clean_html = preg_replace('/<video[^>]*>.*?<\/video>/is', '', $clean_html);
    }

    $clean_html = preg_replace('/<p>\s*<\/p>/', '', $clean_html);
    $clean_html = preg_replace('/<div>\s*<\/div>/', '', $clean_html);
    $clean_html = preg_replace('/  +/', ' ', trim($clean_html));
    $source_structure = ans_content_structure_snapshot($clean_html);

    // Translate title + category (title mein bhi placeholder replace karo pehle)
    $title_ph = str_ireplace($source_brand_variants, $brand_placeholder, $title);
    $title_t = ans_translate_retry($title_ph, $lang, 'auto', 3);
    if ($title_t === '') $title_t = $title_ph;
    $cat_t_chain = [];
    foreach ($category_chain as $cat_name) {
        $cat_t = ans_translate_retry($cat_name, $lang, 'auto', 3);
        $cat_t_chain[] = $cat_t !== '' ? $cat_t : $cat_name;
    }
    $cat_t_chain = array_values(array_filter($cat_t_chain));
    if (empty($cat_t_chain)) {
        $cat_t = ans_translate_retry($category_name, $lang, 'auto', 3);
        $cat_t_chain = [$cat_t !== '' ? $cat_t : $category_name];
    }

    $protected_language_terms = array_values(array_filter(array_unique(array_merge([$my_brand, $my_brand . '.com'], $source_brand_variants))));
    $title_t = str_replace(['MYBRANDTOKEN.com', 'MYBRANDTOKEN'], [$my_brand . '.com', $my_brand], $title_t);
    $title_t = ans_enforce_target_language_text($title_t, $lang, $protected_language_terms);
    $title_t = sanitize_text_field(wp_strip_all_tags($title_t));
    foreach ($cat_t_chain as $cat_idx => $cat_t) {
        $cat_t_chain[$cat_idx] = ans_enforce_target_language_text($cat_t, $lang, $protected_language_terms);
    }
    $cat_t_chain = array_values(array_filter($cat_t_chain));

    // Duplicate check
    $exists = $wpdb->get_var($wpdb->prepare("SELECT ID FROM $wpdb->posts WHERE post_title=%s AND post_status='publish'", $title_t));
    if ($exists && (int) $exists !== (int) $existing_src_post_id) {
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Skipped (Title exists)");
        return;
    }

    // Category
    $cat_ids = ans_ensure_category_chain($cat_t_chain);
    if (empty($cat_ids)) $cat_ids = [1];
    $post_cat_ids = [(int) end($cat_ids)];
    $cat_label = implode(' > ', $cat_t_chain);

    // Translate content in chunks — time lagega par sahi hoga
    $source_word_count = ans_html_word_count($clean_html);
    $content_t = ans_translate_chunked($clean_html, $lang);
    $content_t = ans_strip_article_nav_junk_html($content_t);

    // BRAND RESTORE — Translation ke baad MYBRANDTOKEN ko actual brand name se replace karo
    // Yeh ensure karta hai ki brand name kabhi translate nahi hoga
    $content_t = str_replace(['MYBRANDTOKEN.com', 'MYBRANDTOKEN'], [$my_brand . '.com', $my_brand], $content_t);
    $title_t   = str_replace(['MYBRANDTOKEN.com', 'MYBRANDTOKEN'], [$my_brand . '.com', $my_brand], $title_t);

    $title_t   = ans_enforce_target_language_text($title_t, $lang, $protected_language_terms);
    $content_t = ans_enforce_target_language_html($content_t, $lang, $protected_language_terms);
    $content_t = wp_kses_post($content_t);
    $title_t   = sanitize_text_field(wp_strip_all_tags($title_t));

    $translated_word_count = ans_html_word_count($content_t);
    if ($source_word_count >= 300 && $translated_word_count < max(120, (int) floor($source_word_count * 0.55))) {
        ans_quality_hold_record($url, "translation incomplete: $translated_word_count/$source_word_count words", 'translation');
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Skipped (translation incomplete: $translated_word_count/$source_word_count words). Retry this URL.");
        return;
    }

    $final_structure = ans_content_structure_snapshot($content_t);
    $structure_reason = ans_content_structure_mismatch_reason($source_structure, $final_structure);
    if ($structure_reason !== '') {
        ans_quality_hold_record($url, $structure_reason, 'structure');
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error("Skipped ($structure_reason). Source/final paragraph-heading structure did not match.");
        return;
    }

    if ($title_t === '' || trim(wp_strip_all_tags($content_t)) === '') {
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error('Skipped (empty sanitized content)');
        return;
    }

    $language_issue = ans_target_language_issue_reason($title_t, $content_t, $lang, $protected_language_terms);
    if ($language_issue !== '') {
        ans_quality_hold_record($url, $language_issue, 'translation');
        ans_queue_remove_current($url);
        delete_transient($lock_key);
        wp_send_json_error('Skipped (' . $language_issue . '). Retry this URL.');
        return;
    }

    // Seedha publish — no draft
    $action_label = 'Published';
    if ($existing_src_post_id > 0) {
        $pid = wp_update_post([
            'ID'            => $existing_src_post_id,
            'post_title'    => $title_t,
            'post_content'  => $content_t,
            'post_status'   => $post_status,
            'post_category' => $post_cat_ids,
        ], true);

        if (!is_wp_error($pid) && $pid) {
            update_post_meta($pid, 'ans_src', esc_url_raw($url));
            update_post_meta($pid, '_ans_target_lang', $lang);
            update_post_meta($pid, '_ans_schema_lang', ans_schema_language_code($lang));
        }
        $action_label = 'Updated';
    } else {
        $pid = wp_insert_post([
            'post_title'    => $title_t,
            'post_content'  => $content_t,
            'post_status'   => $post_status,
            'post_category' => $post_cat_ids,
            'meta_input'    => [
                'ans_src' => esc_url_raw($url),
                '_ans_target_lang' => $lang,
                '_ans_schema_lang' => ans_schema_language_code($lang),
            ],
        ], true);
    }

    ans_queue_remove_current($url);
    delete_transient($lock_key);

    if (is_wp_error($pid) || !$pid) {
        wp_send_json_error('DB Insert Error');
        return;
    }

    wp_send_json_success(['msg' => $action_label . " [$cat_label, " . number_format_i18n($translated_word_count) . "w]: " . wp_trim_words($title_t, 6)]);
    return;

    if ($pid) wp_send_json_success(['msg' => "✔ Published [$cat_label]: " . wp_trim_words($title_t, 6)]);
});

// ============================================================
// TRANSLATE HELPERS — V315.1 SAFE CHUNKED VERSION
// ============================================================

// Single text translate (title, category — small strings)
function ans_translate_remote($text, $lang, $source_lang = 'auto') {
    $lang = ans_sanitize_option_value('ans_target_lang', $lang);
    $source_lang = sanitize_key((string) $source_lang);
    if ($source_lang === '') $source_lang = 'auto';
    if (empty($text) || $lang === 'select') return '';

    $res = wp_safe_remote_get(
        'https://translate.googleapis.com/translate_a/single?client=gtx&sl=' . rawurlencode($source_lang) . '&tl=' . rawurlencode($lang) . '&dt=t&q=' . urlencode(trim($text)),
        ['timeout' => 25, 'redirection' => 3, 'reject_unsafe_urls' => true, 'limit_response_size' => 1048576]
    );
    if (is_wp_error($res)) return '';

    $arr = json_decode(wp_remote_retrieve_body($res), true);
    return isset($arr[0]) ? trim(implode('', array_column($arr[0], 0))) : '';
}

function ans_translate_retry($text, $lang, $source_lang = 'auto', $attempts = 3) {
    $attempts = max(1, (int) $attempts);
    for ($i = 0; $i < $attempts; $i++) {
        $translated = ans_translate_remote($text, $lang, $source_lang);
        if ($translated !== '') return $translated;
        if ($i + 1 < $attempts) usleep(200000);
    }
    return '';
}

if (!function_exists('ans_translate')) {
    function ans_translate($text, $lang) {
        $lang = ans_sanitize_option_value('ans_target_lang', $lang);
        if (empty($text) || $lang === 'select') return $text;
        $res = wp_safe_remote_get(
            'https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=' . $lang . '&dt=t&q=' . urlencode(trim($text)),
            ['timeout' => 20, 'redirection' => 3, 'reject_unsafe_urls' => true, 'limit_response_size' => 1048576]
        );
        if (is_wp_error($res)) return $text; // on error return original — no data loss
        $arr = json_decode(wp_remote_retrieve_body($res), true);
        return isset($arr[0]) ? implode('', array_column($arr[0], 0)) : $text;
    }
}

/**
 * CHUNKED HTML TRANSLATION
 *
 * How it works:
 * 1. Split HTML into text nodes + HTML tags
 * 2. Batch text nodes into 1500-char chunks separated by |||
 * 3. Send each chunk as ONE API call (not one per sentence)
 * 4. Split response back using ||| separator
 * 5. Reassemble with original HTML tags
 *
 * Result: Big articles translate in ~5-10 API calls instead of 200+
 * If any chunk fails: original text returned for that chunk (no data loss)
 */
if (!function_exists('ans_translate_chunked')) {
    function ans_translate_chunked($html, $lang) {
        if (empty($html) || $lang === 'select') return $html;

        $SEP = ' [[ANS_TRANSLATE_SPLIT]] ';
        $SEP_PATTERN = '/\s*\[\[ANS_TRANSLATE_SPLIT\]\]\s*/';
        $CHUNK_MAX = 1500;

        // Split into parts: text nodes and HTML tags
        $parts = preg_split('/(<[^>]+>)/', $html, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);

        // Identify text nodes
        $text_indices = [];
        foreach ($parts as $i => $p) {
            if (strpos($p, '<') !== 0 && trim($p) !== '') {
                $text_indices[] = $i;
            }
        }

        if (empty($text_indices)) return $html;

        // Group text nodes into chunks
        $chunks       = [];
        $chunk_map    = [];
        $cur_text     = '';
        $cur_indices  = [];
        $chunk_idx    = 0;

        foreach ($text_indices as $i) {
            $node = $parts[$i];
            if (strlen($cur_text) + strlen($node) + strlen($SEP) > $CHUNK_MAX && !empty($cur_text)) {
                $chunks[$chunk_idx]    = $cur_text;
                $chunk_map[$chunk_idx] = $cur_indices;
                $chunk_idx++;
                $cur_text    = '';
                $cur_indices = [];
            }
            $cur_text    .= $SEP . $node;
            $cur_indices[] = $i;
        }
        if (!empty($cur_text)) {
            $chunks[$chunk_idx]    = $cur_text;
            $chunk_map[$chunk_idx] = $cur_indices;
        }

        // Translate each chunk and map back
        $translated_map = [];
        foreach ($chunks as $ci => $chunk_text) {
            $translated = ans_translate_retry($chunk_text, $lang, 'auto', 2);
            if ($translated === '') $translated = $chunk_text;
            // Split on separator to get individual pieces
            $pieces  = array_values(array_filter(preg_split($SEP_PATTERN, $translated), function($p) { return trim($p) !== ''; }));
            $indices = $chunk_map[$ci];

            if (count($pieces) !== count($indices)) {
                foreach ($indices as $part_idx) {
                    $single = ans_translate_retry($parts[$part_idx], $lang, 'auto', 3);
                    $translated_map[$part_idx] = trim($single) !== '' ? $single : $parts[$part_idx];
                }
                continue;
            }

            foreach ($indices as $j => $part_idx) {
                $translated_map[$part_idx] = isset($pieces[$j]) ? trim($pieces[$j]) : $parts[$part_idx];
            }
        }

        // Reassemble
        $out = '';
        foreach ($parts as $i => $p) {
            $out .= isset($translated_map[$i]) ? $translated_map[$i] : $p;
        }
        return $out;
    }
}

// Legacy wrapper (kept for compatibility)
if (!function_exists('ans_translate_html')) {
    function ans_translate_html($html, $lang) {
        return ans_translate_chunked($html, $lang);
    }
}

function ans_language_plain_text($text) {
    $text = html_entity_decode(wp_strip_all_tags(strip_shortcodes((string) $text)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = preg_replace('/https?:\/\/\S+|www\.\S+|\S+@\S+/i', ' ', $text);
    $text = preg_replace('/\s+/u', ' ', trim($text));
    return $text ?: '';
}

function ans_remove_protected_language_terms($text, $protected_terms = []) {
    foreach ((array) $protected_terms as $term) {
        $term = trim((string) $term);
        if (strlen($term) < 3) continue;
        $text = str_ireplace($term, ' ', $text);
    }
    return preg_replace('/\s+/u', ' ', trim($text));
}

function ans_looks_like_english_text($text, $lang, $protected_terms = []) {
    $lang = ans_sanitize_option_value('ans_target_lang', $lang);
    if ($lang === 'select' || $lang === 'en') return false;

    $plain = ans_remove_protected_language_terms(ans_language_plain_text($text), $protected_terms);
    if (strlen($plain) < 3) return false;

    $lower = function_exists('mb_strtolower') ? mb_strtolower($plain, 'UTF-8') : strtolower($plain);
    if (!preg_match_all('/\b[a-z]{2,}\b/u', $lower, $matches)) return false;

    $words = $matches[0];
    $word_count = count($words);
    if ($word_count === 0) return false;

    $phrase_patterns = [
        '/\b(this|that|these|those)\s+(is|are|was|were)\b/u',
        '/\b(you|your|we|they)\s+(can|should|will|may|have|are|need|look)\b/u',
        '/\b(if|when|while)\s+you\b/u',
        '/\b(here are|check the|check your|know its|also known as|in this article|read more|leave a comment|post comment)\b/u',
        '/\b(egg white|egg yolk|nutritional facts|balanced nutrition|diet and nutrition)\b/u',
    ];
    foreach ($phrase_patterns as $pattern) {
        if (preg_match($pattern, $lower)) return true;
    }

    $english_terms = array_flip([
        'the','and','that','this','these','those','with','from','have','has','had','are','was','were',
        'you','your','they','their','there','which','when','while','where','what','why','how','will',
        'would','should','could','can','may','also','about','into','between','before','after','because',
        'without','within','then','than','other','only','its','itself','food','foods','egg','eggs',
        'white','yolk','nutrition','nutritional','calories','sodium','check','contains','provides',
        'helps','health','healthy','body','diet','weight','loss','heart','know','facts','balanced','beauty'
    ]);

    $hits = 0;
    foreach ($words as $word) {
        if (isset($english_terms[$word])) $hits++;
    }

    if ($word_count <= 8 && $hits >= max(2, (int) ceil($word_count * 0.5)) && !preg_match('/[\x{00e4}\x{00f6}\x{00fc}\x{00df}]/iu', $lower)) {
        return true;
    }

    if ($word_count <= 4) {
        $short_terms = array_flip(['sodium','calories','carbohydrates','cholesterol','yolk','white','contains','nutrition','health','beauty','diet','food','foods','aromatherapy']);
        foreach ($words as $word) {
            if (isset($short_terms[$word])) return true;
        }
    }

    $ratio = $hits / max(1, $word_count);
    return ($hits >= 5 && $ratio >= 0.10) || ($hits >= 3 && $ratio >= 0.18);
}

function ans_enforce_target_language_text($text, $lang, $protected_terms = []) {
    if (!ans_looks_like_english_text($text, $lang, $protected_terms)) return $text;
    $translated = ans_translate_retry($text, $lang, 'en', 3);
    return trim($translated) !== '' ? $translated : $text;
}

function ans_enforce_target_language_html($html, $lang, $protected_terms = []) {
    $lang = ans_sanitize_option_value('ans_target_lang', $lang);
    if (empty($html) || $lang === 'select' || $lang === 'en') return $html;

    $parts = preg_split('/(<[^>]+>)/', $html, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
    if (empty($parts)) return $html;

    foreach ($parts as $i => $part) {
        if (strpos($part, '<') === 0 || trim($part) === '') continue;
        if (!ans_looks_like_english_text($part, $lang, $protected_terms)) continue;

        $translated = ans_translate_retry($part, $lang, 'en', 3);
        if (trim($translated) !== '') $parts[$i] = $translated;
    }

    return implode('', $parts);
}

function ans_target_language_issue_reason($title, $html, $lang, $protected_terms = []) {
    $lang = ans_sanitize_option_value('ans_target_lang', $lang);
    if ($lang === 'select' || $lang === 'en') return '';

    if (ans_looks_like_english_text($title, $lang, $protected_terms)) {
        return 'target language check failed: English title remains';
    }

    $parts = preg_split('/(<[^>]+>)/', (string) $html, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
    foreach ((array) $parts as $part) {
        if (strpos($part, '<') === 0 || trim($part) === '') continue;
        if (!ans_looks_like_english_text($part, $lang, $protected_terms)) continue;

        $sample = ans_language_plain_text($part);
        $sample = sanitize_text_field(wp_trim_words($sample, 10, '...'));
        return 'target language check failed: English content remains near "' . $sample . '"';
    }

    return '';
}

// ============================================================
// BLOGPOSTING SCHEMA ENGINE
// ============================================================
function ans_schema_language_code($lang = '') {
    $lang = sanitize_key((string) $lang);
    $map = [
        'pt' => 'pt',
        'de' => 'de',
        'it' => 'it',
        'es' => 'es',
        'fr' => 'fr',
        'en' => 'en',
        'hi' => 'hi',
        'ru' => 'ru',
    ];

    if (isset($map[$lang])) return $map[$lang];

    $locale = function_exists('determine_locale') ? determine_locale() : get_locale();
    $locale = strtolower(str_replace('_', '-', (string) $locale));
    if (preg_match('/^[a-z]{2}(?:-[a-z]{2})?$/', $locale)) return $locale;

    return 'en';
}

function ans_schema_clean_text($text, $max_chars = 0) {
    $text = strip_shortcodes((string) $text);
    $text = preg_replace('/<(br|hr)\s*\/?>/i', ' ', $text);
    $text = preg_replace('/<\/(p|div|section|article|header|footer|h[1-6]|li|ul|ol|tr|td|th|blockquote)>/i', ' ', $text);
    $text = preg_replace('/<(li|p|div|section|article|h[1-6])\b[^>]*>/i', ' ', $text);
    $text = html_entity_decode(wp_strip_all_tags($text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = preg_replace('/\s+/u', ' ', trim($text));
    if ($max_chars > 0 && function_exists('mb_substr') && mb_strlen($text, 'UTF-8') > $max_chars) {
        $text = rtrim(mb_substr($text, 0, $max_chars, 'UTF-8')) . '...';
    } elseif ($max_chars > 0 && strlen($text) > $max_chars) {
        $text = rtrim(substr($text, 0, $max_chars)) . '...';
    }
    return $text;
}

function ans_schema_site_name() {
    $brand = ans_sanitize_option_value('ans_my_brand', get_option('ans_my_brand', ''));
    $name = trim($brand !== '' ? $brand : (get_bloginfo('name') ?: ''));
    return $name !== '' ? $name : 'Website';
}

function ans_schema_site_description() {
    $description = ans_schema_clean_text(get_bloginfo('description'), 300);
    return $description !== '' ? $description : ans_schema_site_name();
}

function ans_schema_post_language($post_id) {
    $stored = get_post_meta($post_id, '_ans_schema_lang', true);
    if (!empty($stored)) return ans_schema_language_code($stored);

    $target = get_post_meta($post_id, '_ans_target_lang', true);
    if (!empty($target)) return ans_schema_language_code($target);

    return ans_schema_language_code(get_option('ans_target_lang', ''));
}

function ans_schema_image_object($url, $width = 0, $height = 0) {
    if (is_string($url) && strpos($url, '//') === 0) {
        $url = is_ssl() ? 'https:' . $url : 'http:' . $url;
    } elseif (is_string($url) && strpos($url, '/') === 0) {
        $url = home_url($url);
    }

    $url = esc_url_raw($url);
    if (empty($url) || !wp_http_validate_url($url)) return [];

    $image = [
        '@type' => 'ImageObject',
        'url' => $url,
    ];
    if ($width > 0) $image['width'] = (int) $width;
    if ($height > 0) $image['height'] = (int) $height;
    return $image;
}

function ans_schema_logo_image() {
    $custom_logo_id = function_exists('get_theme_mod') ? (int) get_theme_mod('custom_logo') : 0;
    if ($custom_logo_id > 0) {
        $src = wp_get_attachment_image_src($custom_logo_id, 'full');
        if (!empty($src[0])) {
            return ans_schema_image_object($src[0], $src[1] ?? 0, $src[2] ?? 0);
        }
    }

    $site_icon = get_site_icon_url(512);
    if ($site_icon) return ans_schema_image_object($site_icon, 512, 512);

    return [];
}

function ans_schema_post_images($post) {
    $images = [];
    $post_id = is_object($post) ? (int) $post->ID : 0;

    if ($post_id && has_post_thumbnail($post_id)) {
        $thumb_id = get_post_thumbnail_id($post_id);
        $src = wp_get_attachment_image_src($thumb_id, 'full');
        if (!empty($src[0])) {
            $images[] = ans_schema_image_object($src[0], $src[1] ?? 0, $src[2] ?? 0);
        }
    }

    if (empty($images) && !empty($post->post_content) && preg_match_all('/<img\b[^>]+src=["\']([^"\']+)["\']/i', $post->post_content, $matches)) {
        foreach (array_slice(array_unique($matches[1]), 0, 3) as $src) {
            $image = ans_schema_image_object($src);
            if (!empty($image)) $images[] = $image;
        }
    }

    if (empty($images)) {
        $logo = ans_schema_logo_image();
        if (!empty($logo)) $images[] = $logo;
    }

    return array_values(array_filter($images));
}

function ans_schema_publisher() {
    $publisher = [
        '@type' => 'Organization',
        '@id' => home_url('/#organization'),
        'name' => ans_schema_site_name(),
        'url' => home_url('/'),
    ];

    $logo = ans_schema_logo_image();
    if (!empty($logo)) $publisher['logo'] = $logo;

    return $publisher;
}

function ans_schema_organization_node() {
    return ans_schema_publisher();
}

function ans_schema_author_archive_url($author_id, $name = '') {
    $author_id = (int) $author_id;
    $nicename = get_the_author_meta('user_nicename', $author_id);
    $slug = sanitize_title($nicename);

    if ($slug === '' || strpos(rawurldecode((string) $nicename), ' ') !== false || preg_match('/[A-Z\.]/', (string) $nicename)) {
        $slug = sanitize_title($name);
    }

    if ($slug === '') {
        $fallback_url = get_author_posts_url($author_id);
        return trailingslashit(esc_url_raw($fallback_url));
    }

    global $wp_rewrite;
    $author_base = (!empty($wp_rewrite) && !empty($wp_rewrite->author_base)) ? $wp_rewrite->author_base : 'author';
    $path = trim($author_base, '/') . '/' . $slug;

    return trailingslashit(home_url(user_trailingslashit($path)));
}

function ans_schema_author($post) {
    $author_id = (int) $post->post_author;
    $name = get_the_author_meta('display_name', $author_id);
    if (!$name) $name = ans_schema_site_name();
    $author_url = ans_schema_author_archive_url($author_id, $name);

    $author = [
        '@type' => 'Person',
        '@id' => $author_url . '#person',
        'name' => $name,
        'url' => $author_url,
    ];

    return $author;
}

function ans_schema_organization_ref() {
    return ['@id' => home_url('/#organization')];
}

function ans_schema_website_ref() {
    return ['@id' => home_url('/#website')];
}

function ans_schema_blog_ref() {
    return ['@id' => home_url('/#blog')];
}

function ans_schema_blog_node($lang, $blogposting_id = '') {
    $name = ans_schema_site_name();
    $description = ans_schema_site_description();

    $blog = [
        '@type' => 'Blog',
        '@id' => home_url('/#blog'),
        'url' => home_url('/'),
        'name' => $name,
        'description' => $description ?: $name,
        'inLanguage' => ans_schema_language_code($lang),
        'isAccessibleForFree' => true,
        'isPartOf' => ans_schema_website_ref(),
        'author' => ans_schema_organization_ref(),
        'publisher' => ans_schema_organization_ref(),
        'copyrightHolder' => ans_schema_organization_ref(),
        'copyrightYear' => (int) gmdate('Y'),
    ];

    if ($blogposting_id !== '') {
        $blog['blogPost'] = ['@id' => $blogposting_id];
    }

    return $blog;
}

function ans_schema_terms($post_id, $taxonomy) {
    $terms = get_the_terms($post_id, $taxonomy);
    if (empty($terms) || is_wp_error($terms)) return [];

    $names = [];
    foreach ($terms as $term) {
        $name = ans_schema_clean_text($term->name, 80);
        if ($name !== '') $names[] = $name;
    }

    return array_values(array_unique($names));
}

function ans_build_blogposting_schema($post) {
    if (!$post || $post->post_type !== 'post' || $post->post_status !== 'publish') return [];

    $post_id = (int) $post->ID;
    $url = get_permalink($post_id);
    if (!$url) return [];

    $page_id = trailingslashit($url) . '#webpage';
    $blogposting_id = trailingslashit($url) . '#blogposting';
    $lang = ans_schema_post_language($post_id);
    $site_name = ans_schema_site_name();
    $title = ans_schema_clean_text(get_the_title($post_id), 180);
    $description = has_excerpt($post_id)
        ? ans_schema_clean_text(get_the_excerpt($post_id), 300)
        : ans_schema_clean_text(wp_trim_words(ans_schema_clean_text($post->post_content), 38, ''), 300);
    if ($description === '') $description = $title;
    $article_body = ans_schema_clean_text($post->post_content, 12000);

    $categories = ans_schema_terms($post_id, 'category');
    $tags = ans_schema_terms($post_id, 'post_tag');
    $topics = empty($tags) ? ans_get_content_topics($post->post_content) : [];
    $keywords = array_values(array_unique(array_filter(array_merge($tags, $topics))));
    $images = ans_schema_post_images($post);
    $word_count = (int) get_post_meta($post_id, '_ans_word_count', true);
    if ($word_count <= 0) $word_count = str_word_count(wp_strip_all_tags($post->post_content));

    $blogposting = [
        '@type' => 'BlogPosting',
        '@id' => $blogposting_id,
        'mainEntityOfPage' => ['@id' => $page_id],
        'isPartOf' => ans_schema_blog_ref(),
        'url' => $url,
        'headline' => $title,
        'name' => $title,
        'articleBody' => $article_body,
        'description' => $description,
        'inLanguage' => $lang,
        'isAccessibleForFree' => true,
        'copyrightHolder' => ans_schema_organization_ref(),
        'copyrightYear' => (int) get_post_time('Y', true, $post_id),
        'datePublished' => get_post_time(DATE_W3C, true, $post_id),
        'dateModified' => get_post_modified_time(DATE_W3C, true, $post_id),
        'author' => ans_schema_author($post),
        'creator' => ans_schema_author($post),
        'publisher' => ans_schema_publisher(),
        'wordCount' => $word_count,
    ];

    if (!empty($categories)) {
        $blogposting['articleSection'] = $categories;
        $blogposting['about'] = array_map(function($name) {
            return ['@type' => 'Thing', 'name' => $name];
        }, $categories);
    }

    if (!empty($keywords)) {
        $blogposting['keywords'] = implode(', ', array_slice($keywords, 0, 12));
    }

    if (!empty($images)) {
        $blogposting['image'] = $images;
        $blogposting['thumbnailUrl'] = $images[0]['url'];
    }

    $schema = [
        '@context' => 'https://schema.org',
        '@graph' => [
            [
                '@type' => 'WebSite',
                '@id' => home_url('/#website'),
                'url' => home_url('/'),
                'name' => $site_name,
                'inLanguage' => $lang,
                'publisher' => ans_schema_organization_ref(),
                'hasPart' => ans_schema_blog_ref(),
            ],
            ans_schema_organization_node(),
            ans_schema_blog_node($lang, $blogposting_id),
            [
                '@type' => 'WebPage',
                '@id' => $page_id,
                'url' => $url,
                'name' => $title,
                'description' => $description,
                'inLanguage' => $lang,
                'isPartOf' => ans_schema_website_ref(),
                'primaryImageOfPage' => !empty($images) ? $images[0] : null,
                'datePublished' => get_post_time(DATE_W3C, true, $post_id),
                'dateModified' => get_post_modified_time(DATE_W3C, true, $post_id),
                'mainEntity' => ['@id' => $blogposting_id],
            ],
            $blogposting,
        ],
    ];

    if (!empty($categories)) {
        $schema['@graph'][] = [
            '@type' => 'BreadcrumbList',
            '@id' => trailingslashit($url) . '#breadcrumb',
            'itemListElement' => ans_schema_breadcrumb_items($url, $title, $categories, $lang),
        ];
    }

    return ans_schema_remove_empty($schema);
}

function ans_schema_home_label($lang) {
    $labels = [
        'de' => 'Startseite',
        'pt' => 'Início',
        'it' => 'Home',
        'es' => 'Inicio',
        'fr' => 'Accueil',
        'hi' => 'होम',
        'ru' => 'Главная',
        'en' => 'Home',
    ];
    $lang = ans_schema_language_code($lang);
    return $labels[$lang] ?? 'Home';
}

function ans_schema_breadcrumb_items($url, $title, $categories, $lang = '') {
    $items = [
        [
            '@type' => 'ListItem',
            'position' => 1,
            'name' => ans_schema_home_label($lang),
            'item' => home_url('/'),
        ],
    ];

    $position = 2;
    foreach (array_slice($categories, 0, 2) as $category) {
        $items[] = [
            '@type' => 'ListItem',
            'position' => $position++,
            'name' => $category,
        ];
    }

    $items[] = [
        '@type' => 'ListItem',
        'position' => $position,
        'name' => $title,
        'item' => $url,
    ];

    return $items;
}

function ans_schema_remove_empty($value) {
    if (!is_array($value)) return $value;

    $clean = [];
    foreach ($value as $key => $item) {
        $item = ans_schema_remove_empty($item);
        if ($item === null || $item === '' || $item === []) continue;
        $clean[$key] = $item;
    }

    return array_values($clean) === $clean ? array_values($clean) : $clean;
}

add_action('wp_head', 'ans_output_blogposting_schema', 30);
function ans_output_blogposting_schema() {
    if (is_admin() || !is_singular('post')) return;

    $post = get_post();
    $schema = ans_build_blogposting_schema($post);
    if (empty($schema)) return;

    echo "\n<script type=\"application/ld+json\">\n";
    echo wp_json_encode($schema, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    echo "\n</script>\n";
}

// ============================================================
// ADMIN UI
// ============================================================
function ans_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('Permission denied.', 'scrapeengine'));
    }

    $lang        = ans_sanitize_option_value('ans_target_lang', get_option('ans_target_lang', 'select'));
    $status      = ans_sanitize_option_value('ans_post_status', get_option('ans_post_status', 'publish'));
    $sitemap     = ans_sanitize_option_value('ans_sitemap_url', get_option('ans_sitemap_url', ''));
    $import_img  = ans_sanitize_option_value('ans_import_img', get_option('ans_import_img', 'no'));
    $manual_cat  = ans_sanitize_option_value('ans_manual_category', get_option('ans_manual_category', ''));
    $my_brand    = ans_sanitize_option_value('ans_my_brand', get_option('ans_my_brand', get_bloginfo('name')));
    $title_sel   = ans_sanitize_option_value('ans_title_sel', get_option('ans_title_sel', 'h1'));
    $body_sel    = ans_sanitize_option_value('ans_body_sel', get_option('ans_body_sel', '.entry-content'));
    $delay       = ans_sanitize_option_value('ans_scrape_delay', get_option('ans_scrape_delay', 5));
    $map         = get_option('ans_link_map', []);
    if (!is_array($map)) $map = [];
    $map         = array_filter($map, function($v, $k) { return ans_lg_phrase_allowed($k); }, ARRAY_FILTER_USE_BOTH);
    $link_stats  = get_option('ans_link_stats', []);
    $total_links = count($map);
    $last_scan   = get_option('ans_last_scan', 'Never');
    $link_on     = get_option('ans_linking_enabled', 'yes');
    $status_lbl  = ($link_on === 'yes') ? '<span style="color:#22c55e;">● Running</span>' : '<span style="color:#f59e0b;">⏸ Paused</span>';
    $btn_lbl     = ($link_on === 'yes') ? 'PAUSE LINKING' : 'RESUME LINKING';
    $btn_col     = ($link_on === 'yes') ? '#f59e0b' : '#22c55e';
    $quality_hold_count = count(ans_quality_hold_items());
    $nonce       = wp_create_nonce('ans_nonce');
    $languages   = ['select' => '--- Select Target Language ---', 'pt' => 'Portuguese', 'de' => 'German', 'it' => 'Italian', 'es' => 'Spanish', 'fr' => 'French', 'en' => 'English', 'hi' => 'Hindi', 'ru' => 'Russian'];
    ?>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
        :root{--bg:#0a0f1e;--card:#111827;--sidebar:#0d1424;--border:#1e2d45;--primary:#3b82f6;--primary-glow:rgba(59,130,246,.15);--success:#22c55e;--danger:#ef4444;--warning:#f59e0b;--text:#f1f5f9;--muted:#64748b;}
        *{box-sizing:border-box;}
        body{background:#0a0f1e;font-family:'Inter',sans-serif;}
        /* MAIN WRAPPER */
        .aw{display:flex;min-height:100vh;max-width:1400px;margin:0 auto;color:var(--text);}
        /* SIDEBAR */
        .aside{width:240px;min-width:240px;background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:32px;height:calc(100vh - 32px);}
        .aside-brand{padding:28px 24px 20px;border-bottom:1px solid var(--border);}
        .aside-logo{font-size:18px;font-weight:800;color:#fff;display:flex;align-items:center;gap:10px;letter-spacing:-.3px;}
        .aside-logo .dashicons{color:var(--primary);font-size:20px;}
        .aside-badge{background:var(--primary);font-size:10px;padding:3px 8px;border-radius:20px;font-weight:700;letter-spacing:.5px;}
        .aside-nav{flex:1;padding:16px 12px;}
        .aside-section{font-size:10px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:1px;padding:8px 12px 6px;margin-top:8px;}
        .anav{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:8px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;transition:all .15s;border:none;background:transparent;width:100%;text-align:left;margin-bottom:2px;}
        .anav:hover{color:#fff;background:rgba(255,255,255,.05);}
        .anav.active{color:#fff;background:var(--primary-glow);border:1px solid rgba(59,130,246,.3);}
        .anav.active .nav-icon{color:var(--primary);}
        .nav-icon{font-size:16px;width:18px;text-align:center;color:var(--muted);}
        .nav-label{flex:1;}
        .nav-badge{background:var(--primary);color:#fff;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:700;}
        .aside-footer{padding:16px 20px;border-top:1px solid var(--border);}
        .aside-footer-btn{width:100%;padding:10px;border-radius:8px;border:none;background:var(--primary);color:#fff;font-weight:600;cursor:pointer;font-size:13px;transition:all .2s;}
        .aside-footer-btn:hover{background:#2563eb;}
        /* MAIN CONTENT */
        .amain{flex:1;min-width:0;background:var(--bg);}
        .atopbar{background:linear-gradient(135deg,#0d1628 0%,#111827 100%);border-bottom:1px solid #1e2d45;padding:0;display:flex;justify-content:space-between;align-items:stretch;}
        .apage-title{font-size:20px;font-weight:800;color:#fff;letter-spacing:-.3px;}
        .apage-sub{font-size:12px;color:var(--muted);margin-top:2px;}
        .abody{padding:32px;min-height:calc(100vh - 70px);}
        .atc{display:none;}.atc.active{display:block;}
        .agrid{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-bottom:30px;}
        .albl{display:block;font-size:12px;text-transform:uppercase;color:var(--muted);font-weight:700;margin-bottom:8px;}
        .ainp,.asel,.atxt{width:100%;background:var(--card);border:1px solid var(--border);color:#fff;padding:14px;border-radius:8px;font-size:14px;box-sizing:border-box;}
        .atxt{height:140px;font-family:monospace;font-size:12px;}
        .abtn{padding:12px 24px;border:none;border-radius:6px;font-weight:600;color:#fff;cursor:pointer;transition:all .2s;font-size:14px;text-transform:uppercase;letter-spacing:.5px;box-shadow:0 4px 6px rgba(0,0,0,.1);}
        .abtn:hover{transform:translateY(-2px);}
        .btn-save{background:var(--primary);}
        .btn-fetch{background:#475569;}
        .btn-clean{background:var(--primary);}
        .btn-parse{background:var(--warning);color:#000;}
        .btn-start{background:var(--success);}
        .btn-stop{background:var(--danger);opacity:.5;}
        .btn-kill{background:var(--danger);}
        .amanual{background:var(--card);padding:25px;border-radius:10px;border:1px solid var(--border);margin-bottom:30px;border-left:4px solid var(--warning);}
        .aact{display:flex;gap:15px;margin-bottom:25px;align-items:center;flex-wrap:wrap;}
        .aterm{background:#020617;border-radius:10px;border:1px solid var(--border);overflow:hidden;margin-top:20px;}
        .atbar{background:var(--card);padding:12px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;font-size:12px;font-weight:700;}
        .alogs{height:260px;overflow-y:auto;padding:20px;font-family:'Courier New',monospace;font-size:13px;color:#4ade80;}
        .ali{margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,.05);padding-bottom:6px;}
        .lerr{color:#f87171;}.lwarn{color:#f59e0b;}
        .astat{display:flex;gap:20px;margin-bottom:30px;}
        .asc{background:var(--bg);flex:1;padding:20px;border-radius:8px;border:1px solid var(--border);border-bottom:4px solid var(--primary);position:relative;}
        .asc h3{color:var(--muted);font-size:12px;text-transform:uppercase;margin:0;}
        .asc .val{font-size:28px;font-weight:700;margin-top:10px;}
        .asteps{display:flex;gap:15px;align-items:center;margin-bottom:30px;flex-wrap:wrap;}
        .astep{flex:1;min-width:150px;text-align:center;padding:20px;background:var(--bg);border-radius:8px;border:1px solid var(--border);}
        .ftbl{width:100%;border-collapse:collapse;}
        .ftbl th{background:var(--card);text-align:left;padding:16px;color:var(--muted);font-size:13px;border-bottom:1px solid var(--border);}
        .ftbl td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px;color:#cbd5e1;vertical-align:middle;}
        .bkey{background:#064e3b;color:#34d399;padding:4px 10px;border-radius:20px;font-size:12px;border:1px solid #059669;}
        .dico{color:var(--danger);cursor:pointer;font-weight:bold;font-size:18px;}
        .bact{padding:10px 15px;background:var(--card);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
        .pbwrap{width:100%;height:10px;background:var(--border);border-radius:5px;margin-top:10px;display:none;overflow:hidden;}
        .pbfill{height:100%;width:0%;background:var(--primary);transition:width .3s;}
        .stabs{display:flex;margin-bottom:10px;border-bottom:1px solid var(--border);}
        .stab{background:transparent;border:none;color:var(--muted);padding:10px 20px;cursor:pointer;border-bottom:2px solid transparent;font-size:14px;}
        .stab.active{color:#fff;border-bottom-color:var(--primary);}
        .ftblc{background:var(--bg);border-radius:8px;border:1px solid var(--border);overflow:hidden;margin-top:15px;}
        .tbtn{position:absolute;top:20px;right:20px;padding:5px 10px;border-radius:4px;font-weight:bold;cursor:pointer;border:none;font-size:11px;}
        .prog-wrap{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:15px 20px;margin-bottom:20px;display:none;}
        .prog-bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-top:8px;}
        .prog-fill{height:100%;width:0%;background:var(--primary);transition:width .3s;}
        .stat-row{display:flex;gap:12px;margin-top:10px;font-size:12px;color:var(--muted);align-items:center;flex-wrap:wrap;}
        .stat-chip{background:transparent;border:none;color:var(--muted);padding:4px 0;font:inherit;display:inline-flex;align-items:center;gap:4px;}
        .stat-click{cursor:pointer;border-bottom:1px dashed currentColor;}
        .stat-click:hover{color:#fff;}
        .result-panel{background:var(--card);border:1px solid var(--border);border-radius:8px;margin:-8px 0 20px;display:none;overflow:hidden;}
        .result-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:14px 18px;border-bottom:1px solid var(--border);flex-wrap:wrap;}
        .result-title{font-size:13px;font-weight:800;color:#fff;text-transform:uppercase;letter-spacing:.5px;}
        .result-meta{font-size:12px;color:var(--muted);margin-top:3px;}
        .result-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
        .mini-btn{border:none;border-radius:5px;padding:8px 12px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.4px;cursor:pointer;color:#fff;background:#334155;}
        .mini-btn.primary{background:var(--primary);}
        .mini-btn.warn{background:var(--warning);color:#111827;}
        .mini-btn.danger{background:var(--danger);}
        .result-body{max-height:320px;overflow:auto;}
        .result-table{width:100%;border-collapse:collapse;}
        .result-table th{position:sticky;top:0;background:#0d1424;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;text-align:left;padding:10px;border-bottom:1px solid var(--border);}
        .result-table td{padding:10px;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px;color:#cbd5e1;vertical-align:top;}
        .result-url{color:#93c5fd;text-decoration:none;word-break:break-all;}
        .result-url:hover{text-decoration:underline;}
        .reason-pill{display:inline-block;max-width:420px;color:#f8fafc;line-height:1.4;}
        .result-empty{padding:18px;color:var(--muted);font-size:13px;}
        .speed-wrap{background:var(--card);border:1px solid #3b82f6;border-radius:8px;padding:15px;margin-bottom:20px;}
        .dupbox{text-align:center;padding:40px;background:var(--card);border-radius:12px;border:1px solid var(--border);}
        #dup_result_area{background:var(--bg);border-radius:8px;margin-top:20px;display:none;border:1px solid #475569;text-align:left;max-height:400px;overflow-y:auto;}
        .ditem{border-bottom:1px solid var(--border);padding:15px;display:flex;justify-content:space-between;align-items:center;background:var(--card);}
        .dtitle{font-weight:bold;color:#cbd5e1;font-size:14px;display:flex;align-items:center;gap:10px;}
        .dcnt{background:var(--warning);color:#000;padding:4px 10px;border-radius:12px;font-size:11px;font-weight:bold;}
        .ddel{background:var(--danger);color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:12px;}
    </style>

    <div class="aw">
        <!-- SIDEBAR -->
        <div class="aside">
            <div class="aside-brand">
                <div style="display:flex;align-items:center;gap:10px;">
                    <!-- ScapeCore Logo Mark -->
                    <div style="width:34px;height:34px;background:linear-gradient(135deg,#3b82f6 0%,#6366f1 100%);border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 0 12px rgba(99,102,241,.4);">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="white" stroke-width="2" stroke-linejoin="round"/>
                            <path d="M2 17L12 22L22 17" stroke="white" stroke-width="2" stroke-linejoin="round"/>
                            <path d="M2 12L12 17L22 12" stroke="white" stroke-width="2" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <div>
                        <div style="font-size:15px;font-weight:800;color:#fff;letter-spacing:-.3px;line-height:1;">ScapeCore</div>
                        <div style="font-size:10px;color:#3b82f6;font-weight:600;letter-spacing:.5px;margin-top:2px;">V315.3</div>
                    </div>
                </div>
            </div>
            <nav class="aside-nav">
                <div class="aside-section">Main</div>
                <button class="anav active" onclick="openTab('tab1',this)" data-page="Scraper" data-sub="Fetch, parse and publish content">
                    <span class="nav-icon dashicons dashicons-download"></span>
                    <span class="nav-label">Scraper</span>
                </button>
                <div class="aside-section">Tools</div>
                <button class="anav" onclick="openTab('tab2',this)" data-page="Content Purity" data-sub="Detect and eliminate duplicate content">
                    <span class="nav-icon dashicons dashicons-trash"></span>
                    <span class="nav-label">Content Purity</span>
                </button>
                <button class="anav" onclick="openTab('tab3',this)" data-page="LinkGraph" data-sub="Intelligent internal link automation">
                    <span class="nav-icon dashicons dashicons-admin-links"></span>
                    <span class="nav-label">LinkGraph</span>
                    <?php if($total_links > 0): ?><span class="nav-badge"><?php echo intval($total_links); ?></span><?php endif; ?>
                </button>
            </nav>
            <div class="aside-footer">
                <button id="save_btn" class="aside-footer-btn">Save Config</button>
            </div>
        </div>
        <!-- MAIN -->
        <div class="amain">
            <div class="atopbar">
                <!-- Left accent bar -->
                <div style="width:3px;background:linear-gradient(180deg,#3b82f6,#6366f1);align-self:stretch;flex-shrink:0;"></div>
                <!-- Page title area -->
                <div style="padding:14px 24px;flex:1;">
                    <div class="apage-title" id="page-title">Scraper</div>
                    <div class="apage-sub" id="page-sub">Fetch, parse and publish content</div>
                </div>
            </div>
            <div class="abody">

            <!-- TAB 1 -->
            <div id="tab1" class="atc active">
                <div class="agrid">
                    <div>
                        <div style="margin-bottom:20px;"><label class="albl">Target Language</label>
                            <select id="ans_target_lang" class="asel"><?php foreach($languages as $c=>$n): ?><option value="<?php echo esc_attr($c);?>" <?php selected($lang,$c);?>><?php echo esc_html($n);?></option><?php endforeach;?></select>
                        </div>
                        <div style="margin-bottom:20px;"><label class="albl">Post Status</label>
                            <select id="ans_post_status" class="asel"><option value="draft" <?php selected($status,'draft');?>>Draft</option><option value="publish" <?php selected($status,'publish');?>>Publish</option></select>
                        </div>
                        <div style="margin-bottom:20px;"><label class="albl">Content Mode</label>
                            <select id="ans_import_img" class="asel"><option value="no" <?php selected($import_img,'no');?>>Text Only</option><option value="yes" <?php selected($import_img,'yes');?>>Full Content</option></select>
                        </div>
                        <div style="margin-bottom:20px;border:1px solid var(--primary);padding:15px;border-radius:8px;">
                            <label class="albl" style="color:var(--primary);">Manual Category (Optional)</label>
                            <input type="text" id="ans_manual_category" class="ainp" value="<?php echo esc_attr($manual_cat);?>" placeholder="e.g. Health">
                        </div>
                        <div style="border:1px solid var(--warning);padding:15px;border-radius:8px;">
                            <label class="albl" style="color:var(--warning);">My Brand Name</label>
                            <input type="text" id="ans_my_brand" class="ainp" value="<?php echo esc_attr($my_brand);?>">
                        </div>
                    </div>
                    <div>
                        <div style="margin-bottom:20px;"><label class="albl">Sitemap URL</label><input type="text" id="ans_sitemap_url" class="ainp" value="<?php echo esc_attr($sitemap);?>"></div>
                        <div style="margin-bottom:20px;"><label class="albl">Title Selector</label><input type="text" id="ans_title_sel" class="ainp" value="<?php echo esc_attr($title_sel);?>"></div>
                        <div style="margin-bottom:20px;"><label class="albl">Body Selector</label><input type="text" id="ans_body_sel" class="ainp" value="<?php echo esc_attr($body_sel);?>" style="border-color:var(--success);"></div>
                        <!-- SPEED CONTROL -->
                        <div class="speed-wrap">
                            <label class="albl" style="color:var(--primary);">Speed Control — Delay Between Posts</label>
                            <div style="display:flex;align-items:center;gap:15px;margin-top:10px;">
                                <input type="range" id="ans_scrape_delay" min="2" max="30" value="<?php echo esc_attr($delay);?>" style="flex:1;accent-color:var(--primary);">
                                <span id="delay_val" style="color:#fff;font-weight:700;min-width:60px;"><?php echo esc_html($delay);?>s</span>
                            </div>
                            <small style="color:var(--muted);">Slower = safer (less chance of being blocked). Faster = more risk.</small>
                        </div>
                    </div>
                </div>

                <!-- PROGRESS BAR -->
                <div class="prog-wrap" id="progress_wrap">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span style="font-weight:700;color:#fff;">Scraping Progress</span>
                        <span id="prog_text" style="color:var(--muted);font-size:13px;">0 done</span>
                    </div>
                    <div class="prog-bar"><div class="prog-fill" id="prog_fill"></div></div>
                    <div class="stat-row">
                        <span class="stat-chip">Success: <strong id="stat_success" style="color:var(--success);">0</strong></span>
                        <button type="button" class="stat-chip stat-click" data-result-type="fail">Failed: <strong id="stat_fail" style="color:var(--danger);">0</strong></button>
                        <button type="button" class="stat-chip stat-click" data-result-type="skip">Skipped: <strong id="stat_skip" style="color:var(--warning);">0</strong></button>
                        <button type="button" class="stat-chip stat-click" id="quality_hold_btn">Review Later: <strong id="quality_hold_count" style="color:#f97316;"><?php echo esc_html(number_format_i18n($quality_hold_count));?></strong></button>
                        <span class="stat-chip">Avg Speed: <strong id="stat_speed" style="color:var(--primary);">-</strong></span>
                    </div>
                </div>

                <div class="result-panel" id="result_panel">
                    <div class="result-head">
                        <div>
                            <div class="result-title" id="result_title">Failed URLs</div>
                            <div class="result-meta" id="result_meta">Click Failed or Skipped to view post URLs and reasons.</div>
                        </div>
                        <div class="result-actions">
                            <button type="button" class="mini-btn" id="result_select_toggle">Select All</button>
                            <button type="button" class="mini-btn warn" id="result_retry_selected">Retry Selected</button>
                            <button type="button" class="mini-btn primary" id="result_retry_all">Retry All</button>
                            <button type="button" class="mini-btn danger" id="result_close">Close</button>
                        </div>
                    </div>
                    <div class="result-body" id="result_body"></div>
                </div>

                <div class="result-panel" id="quality_hold_panel">
                    <div class="result-head">
                        <div>
                            <div class="result-title">Review Later URLs</div>
                            <div class="result-meta" id="quality_hold_meta">Structure/quality mismatch URLs saved for later retry.</div>
                        </div>
                        <div class="result-actions">
                            <button type="button" class="mini-btn" id="quality_hold_select_toggle">Select All</button>
                            <button type="button" class="mini-btn warn" id="quality_hold_retry_selected">Retry Selected</button>
                            <button type="button" class="mini-btn primary" id="quality_hold_retry_all">Retry All</button>
                            <button type="button" class="mini-btn danger" id="quality_hold_delete_selected">Delete Selected</button>
                            <button type="button" class="mini-btn danger" id="quality_hold_close">Close</button>
                        </div>
                    </div>
                    <div class="result-body" id="quality_hold_body"></div>
                </div>

                <div class="amanual">
                    <div style="color:var(--warning);font-size:12px;font-weight:700;margin-bottom:10px;">MANUAL DATA INPUT</div>
                    <textarea id="manual_sitemap_data" class="atxt" placeholder="Paste URLs here (one per line or comma separated)..."></textarea>
                    <div style="margin-top:15px;"><button id="manual_parse_btn" class="abtn btn-parse">Parse Pasted Data</button></div>
                </div>

                <div class="aact">
                    <button id="fetch_btn" class="abtn btn-fetch">Fetch via Browser</button>
                    <button id="clean_queue_btn" class="abtn btn-clean">🧹 Clean Queue</button>
                    <div style="flex-grow:1;"></div>
                    <button id="start_btn" class="abtn btn-start">START ENGINE</button>
                    <button id="stop_btn" class="abtn btn-stop" disabled>STOP</button>
                </div>

                <div class="aterm">
                    <div class="atbar" style="display:flex;justify-content:space-between;align-items:center;padding:10px 16px;">
                        <div style="display:flex;align-items:center;gap:20px;">
                            <span style="color:#94a3b8;font-weight:700;font-size:11px;letter-spacing:1px;text-transform:uppercase;">Live Logs</span>
                            <div style="display:flex;align-items:center;gap:8px;background:#0d1424;border:1px solid #1e2d45;border-radius:6px;padding:5px 14px;">
                                <span style="width:7px;height:7px;border-radius:50%;background:#f59e0b;display:inline-block;animation:blink 1.2s infinite;flex-shrink:0;"></span>
                                <span style="font-size:11px;color:#64748b;font-weight:500;text-transform:uppercase;letter-spacing:.5px;">Queue</span>
                                <strong id="q_count" style="font-size:14px;color:#ffffff;font-weight:800;min-width:20px;text-align:center;">0</strong>
                                <span style="font-size:11px;color:#475569;">URLs</span>
                            </div>
                        </div>
                        <button id="clear_btn" style="background:#1e293b;color:#ef4444;border:1px solid #2d3f55;padding:5px 14px;border-radius:5px;cursor:pointer;font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;">Clear</button>
                    </div>
                    <style>
                        @keyframes blink{0%,100%{opacity:1;box-shadow:0 0 5px #f59e0b;}50%{opacity:.3;box-shadow:none;}}
                        .atopbar{background:linear-gradient(135deg,#111827 0%,#0d1424 100%);border-bottom:1px solid #1e2d45;padding:18px 32px;display:flex;justify-content:space-between;align-items:center;}
                        .apage-title{font-size:22px;font-weight:800;color:#fff;letter-spacing:-.3px;}
                        .apage-sub{font-size:12px;color:#475569;margin-top:3px;font-weight:400;}
                    </style>
                    <div id="logs" class="alogs"><div class="ali">System Ready. V315.3 Loaded.</div></div>
                </div>
            </div>

            <!-- TAB 2 — CONTENT PURITY -->
            <div id="tab2" class="atc">
                <!-- Top stats row -->
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:32px;">
                    <div style="background:var(--card);border:1px solid var(--border);border-left:4px solid var(--danger);border-radius:10px;padding:20px;">
                        <div style="font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;">Duplicate Sets</div>
                        <div id="dup_stat_sets" style="font-size:32px;font-weight:800;color:#fff;margin-top:6px;">—</div>
                        <div style="font-size:12px;color:var(--muted);margin-top:4px;">Groups of identical posts</div>
                    </div>
                    <div style="background:var(--card);border:1px solid var(--border);border-left:4px solid var(--warning);border-radius:10px;padding:20px;">
                        <div style="font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;">Posts to Remove</div>
                        <div id="dup_stat_posts" style="font-size:32px;font-weight:800;color:#fff;margin-top:6px;">—</div>
                        <div style="font-size:12px;color:var(--muted);margin-top:4px;">Keeping 1 original per group</div>
                    </div>
                    <div style="background:var(--card);border:1px solid var(--border);border-left:4px solid var(--success);border-radius:10px;padding:20px;">
                        <div style="font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;">Delete Mode</div>
                        <div style="margin-top:10px;">
                            <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                                <div style="position:relative;">
                                    <input type="checkbox" id="perm_delete_chk" style="opacity:0;position:absolute;width:0;">
                                    <div id="toggle_track" style="width:44px;height:24px;background:#334155;border-radius:12px;transition:all .2s;cursor:pointer;" onclick="toggleMode()">
                                        <div id="toggle_thumb" style="width:20px;height:20px;background:#fff;border-radius:50%;margin:2px;transition:all .2s;"></div>
                                    </div>
                                </div>
                                <div>
                                    <div id="mode_label" style="font-size:14px;font-weight:600;color:#fff;">Move to Trash</div>
                                    <div id="mode_sub" style="font-size:11px;color:var(--muted);">Recoverable</div>
                                </div>
                            </label>
                        </div>
                    </div>
                </div>

                <!-- Action bar -->
                <div style="display:flex;gap:12px;margin-bottom:24px;align-items:center;">
                    <button id="scan_dup_btn" style="background:var(--primary);color:#fff;border:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px;cursor:pointer;letter-spacing:.3px;">
                        Scan for Duplicates
                    </button>
                    <div id="bulk_actions_area" style="display:none;">
                        <button id="confirm_del_btn" style="background:var(--danger);color:#fff;border:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px;cursor:pointer;">
                            Remove All Duplicates
                        </button>
                    </div>
                    <div id="del_progress" style="display:none;flex:1;">
                        <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden;">
                            <div class="prog-fill" id="del_prog_fill" style="height:100%;"></div>
                        </div>
                        <div id="del_prog_text" style="font-size:12px;color:var(--muted);margin-top:5px;"></div>
                    </div>
                </div>

                <!-- Results table -->
                <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
                    <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                        <span style="font-weight:600;color:#fff;font-size:14px;">Scan Results</span>
                        <span id="dup_scan_status" style="font-size:12px;color:var(--muted);">Run a scan to see results</span>
                    </div>
                    <div id="dup_result_area" style="max-height:420px;overflow-y:auto;"></div>
                    <div id="dup_logs" class="alogs" style="height:120px;border-top:1px solid var(--border);"><div class="ali">Ready to scan...</div></div>
                </div>
            </div>

            <!-- TAB 3 — LINKGRAPH -->
            <div id="tab3" class="atc">

                <!-- KPI Row -->
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:32px;">
                    <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:22px;display:flex;justify-content:space-between;align-items:flex-start;">
                        <div>
                            <div style="font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;">Link Engine</div>
                            <div id="status-text" style="font-size:22px;font-weight:700;margin-top:8px;"><?php echo wp_kses($status_lbl, ['span' => ['style' => true]]);?></div>
                        </div>
                        <button id="btn-toggle-link" style="background:<?php echo esc_attr($btn_col);?>;color:#fff;border:none;padding:8px 14px;border-radius:6px;font-size:11px;font-weight:700;cursor:pointer;letter-spacing:.5px;"><?php echo esc_html($btn_lbl);?></button>
                    </div>
                    <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:22px;">
                        <div style="font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;">3+ Word Anchors</div>
                        <div style="font-size:36px;font-weight:800;color:#fff;margin-top:8px;"><?php echo esc_html(number_format($total_links));?></div>
                        <div style="font-size:12px;color:var(--muted);margin-top:4px;">Enterprise phrase rules</div>
                    </div>
                    <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:22px;">
                        <div style="font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;">Last Analysis</div>
                        <div style="font-size:16px;font-weight:600;color:#fff;margin-top:12px;"><?php echo esc_html($last_scan);?></div>
                        <div style="font-size:12px;color:var(--muted);margin-top:6px;"><?php echo !empty($link_stats['scanned']) ? intval($link_stats['scanned']).' / '.intval($link_stats['total']).' posts indexed' : '3+ word phrases only';?></div>
                    </div>
                </div>

                <!-- Workflow Pipeline -->
                <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:24px;margin-bottom:28px;">
                    <div style="font-size:12px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.8px;margin-bottom:20px;">Workflow</div>
                    <div style="display:grid;grid-template-columns:1fr 32px 1fr 32px 1fr 32px 1fr;align-items:center;gap:0;">
                        <!-- Step 1 -->
                        <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:center;">
                            <div style="width:28px;height:28px;background:var(--primary);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;font-size:12px;font-weight:700;">1</div>
                            <div style="font-size:12px;color:var(--muted);margin-bottom:12px;">Build 3+ Word Graph</div>
                            <button id="btn-link-scan" style="width:100%;background:var(--primary);color:#fff;border:none;padding:10px;border-radius:6px;font-weight:600;font-size:12px;cursor:pointer;">Start Analysis</button>
                            <div class="pbwrap" style="margin-top:8px;"><div id="scan-bar" class="pbfill"></div></div>
                            <div id="scan-text" style="font-size:11px;color:var(--muted);margin-top:6px;">No 1-2 word anchors</div>
                        </div>
                        <div style="text-align:center;color:#334155;font-size:18px;">→</div>
                        <!-- Step 2 -->
                        <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:center;">
                            <div style="width:28px;height:28px;background:#10b981;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;font-size:12px;font-weight:700;">2</div>
                            <div style="font-size:12px;color:var(--muted);margin-bottom:12px;">Check Opportunities</div>
                            <button id="btn-link-report" style="width:100%;background:#10b981;color:#fff;border:none;padding:10px;border-radius:6px;font-weight:600;font-size:12px;cursor:pointer;">Check 3+ Word Links</button>
                            <div style="font-size:11px;color:var(--muted);margin-top:6px;">50 posts at a time</div>
                        </div>
                        <div style="text-align:center;color:#334155;font-size:18px;">→</div>
                        <!-- Step 3 -->
                        <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:center;">
                            <div style="width:28px;height:28px;background:var(--warning);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;font-size:12px;font-weight:700;color:#000;">3</div>
                            <div style="font-size:12px;color:var(--muted);margin-bottom:12px;">Apply to All Posts</div>
                            <button id="btn-apply-links" style="width:100%;background:var(--warning);color:#000;border:none;padding:10px;border-radius:6px;font-weight:700;font-size:12px;cursor:pointer;">Apply Permanently</button>
                            <button id="btn-apply-all-links" style="width:100%;background:#f97316;color:#111827;border:none;padding:10px;border-radius:6px;font-weight:800;font-size:12px;cursor:pointer;margin-top:8px;">Auto Apply All</button>
                            <div id="apply-status" style="font-size:11px;color:var(--success);margin-top:6px;"></div>
                        </div>
                        <div style="text-align:center;color:#334155;font-size:18px;">→</div>
                        <!-- Step 4 -->
                        <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:center;">
                            <div style="width:28px;height:28px;background:#475569;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;font-size:12px;font-weight:700;">4</div>
                            <div style="font-size:12px;color:var(--muted);margin-bottom:12px;">Reset</div>
                            <button id="btn-link-clear" style="width:100%;background:#475569;color:#fff;border:none;padding:10px;border-radius:6px;font-weight:600;font-size:12px;cursor:pointer;">Clear All Data</button>
                            <div style="font-size:11px;color:var(--muted);margin-top:6px;">Start fresh</div>
                        </div>
                    </div>
                </div>

                <!-- Data Tabs -->
                <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
                    <div style="display:flex;border-bottom:1px solid var(--border);">
                        <button class="stab active" onclick="openSubTab(event,'st-map')" style="padding:14px 24px;background:transparent;border:none;color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;">3+ Word Rules</button>
                        <button class="stab" onclick="openSubTab(event,'st-report')" style="padding:14px 24px;background:transparent;border:none;color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;">Link Report</button>
                        <button class="stab" onclick="openSubTab(event,'st-orphans')" style="padding:14px 24px;background:transparent;border:none;color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;">Unlinked Posts</button>
                        <div style="flex:1;display:flex;align-items:center;justify-content:flex-end;padding:0 16px;gap:8px;">
                            <button id="btn-sel-all" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 12px;border-radius:5px;font-size:12px;cursor:pointer;">Select All</button>
                            <span id="range-display" style="color:var(--muted);font-size:12px;"></span>
                        </div>
                    </div>
                <!-- Mapped Rules -->
                <div id="st-map" class="stc">
                    <div class="ftblc" style="border:none;border-radius:0;">
                        <div class="bact" style="background:transparent;border-bottom:1px solid var(--border);">
                            <button class="abtn btn-kill bulk-del-btn" style="padding:5px 12px;font-size:12px;" disabled>Delete Selected</button>
                            <small style="color:var(--danger);">Removes 3+ word anchor rules.</small>
                        </div>
                        <table class="ftbl">
                            <thead><tr><th width="5%"><input type="checkbox" class="cb-all"></th><th>Anchor Phrase</th><th>Target Post</th><th width="8%">Words</th><th width="8%">Score</th><th width="10%">Source</th><th width="8%">Remove</th></tr></thead>
                            <tbody>
                                <?php if(!empty($map)):$c=0;foreach($map as $k=>$v){if($c++>200)break;?>
                                <tr>
                                    <td><input type="checkbox" class="cb-row" value="<?php echo esc_attr($k);?>"></td>
                                    <td><span class="bkey"><?php echo esc_html($k);?></span></td>
                                    <td><a href="<?php echo esc_url($v['url']);?>" target="_blank" style="color:var(--primary);"><?php echo esc_html($v['title']);?></a></td>
                                    <td><?php echo intval($v['words'] ?? ans_lg_phrase_word_count($k));?></td>
                                    <td><?php echo intval($v['score'] ?? 0);?></td>
                                    <td><?php echo esc_html(strtoupper($v['source'] ?? 'BODY'));?></td>
                                    <td style="text-align:center;"><span class="dico" onclick="deleteLinkSingle('<?php echo esc_js($k);?>')">&times;</span></td>
                                </tr>
                                <?php }else:echo '<tr><td colspan="7" style="padding:30px;text-align:center;color:var(--muted);">No data. Run Step 1 to build 3+ word anchors.</td></tr>';endif;?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <!-- Live Report -->
                <div id="st-report" class="stc" style="display:none;">
                    <div class="ftblc" style="border:none;border-radius:0;">
                        <div class="bact" style="background:transparent;border-bottom:1px solid var(--border);">
                            <button id="btn-load-more" class="abtn" style="background:var(--primary);padding:5px 15px;">Load Next 50 Posts</button>
                        </div>
                        <table class="ftbl">
                            <thead><tr><th width="4%"></th><th>Source Post</th><th>3+ Word Anchor</th><th>Target</th><th width="12%">Confidence</th><th width="8%">Remove</th></tr></thead>
                            <tbody id="report-body"><tr><td colspan="6" style="text-align:center;padding:30px;color:var(--muted);">Click "Check 3+ Word Links" to start.</td></tr></tbody>
                        </table>
                    </div>
                </div>
                <!-- Orphan Posts -->
                <div id="st-orphans" class="stc" style="display:none;">
                    <div class="ftblc" style="border:none;border-radius:0;">
                        <div class="bact" style="background:transparent;border-bottom:1px solid var(--border);">
                            <button id="btn-find-orphans" class="abtn" style="background:#7c3aed;padding:5px 15px;">Find Unlinked Posts</button>
                            <div class="pbwrap" id="orphan-pb-wrap" style="flex:1;display:none;"><div id="orphan-bar" class="pbfill"></div></div>
                            <small id="orphan-status" style="color:var(--muted);font-size:12px;"></small>
                        </div>
                        <table class="ftbl">
                            <thead><tr><th>Post Title</th><th>URL</th></tr></thead>
                            <tbody id="orphan-body"><tr><td colspan="2" style="text-align:center;padding:30px;color:var(--muted);">Click "Find Orphan Posts" to scan.</td></tr></tbody>
                        </table>
                    </div>
                </div><!-- end data tabs container -->
            </div><!-- end tab3 -->

        </div><!-- end abody -->
        </div><!-- end amain -->
    </div><!-- end aw -->

    <script>
    var ANS_NONCE = '<?php echo esc_js($nonce); ?>';
    var reportOffset = 0;
    var orphanOffset = 0;
    var BLOCKED_EXTS = ['jpg','jpeg','png','gif','webp','svg','bmp','ico','mp4','mp3','wav','ogg','pdf','zip','rar','css','js','woff','woff2','ttf','eot','xml','json'];
    var stats = { success: 0, fail: 0, skip: 0, times: [] };
    var totalQueue = 0;
    var resultDetails = { fail: [], skip: [] };
    var activeResultType = 'fail';

    function isMediaUrl(u) {
        try { var e = u.split('?')[0].split('.').pop().toLowerCase(); return BLOCKED_EXTS.indexOf(e) !== -1; } catch(e) { return false; }
    }
    function openTab(id, el) {
        jQuery('.atc').removeClass('active');
        jQuery('.anav').removeClass('active');
        jQuery('#'+id).addClass('active');
        jQuery(el).addClass('active');
        var page = jQuery(el).data('page') || '';
        var sub  = jQuery(el).data('sub') || '';
        if(page) {
            jQuery('#page-title').text(page);
            jQuery('#page-sub').text(sub);
        }
    }
    function openSubTab(evt, id) {
        jQuery('.stc').hide(); jQuery('.stab').removeClass('active');
        jQuery('#'+id).show(); evt.currentTarget.classList.add('active');
    }
    function deleteLinkSingle(kw) {
        if(!confirm('Remove this keyword rule?')) return;
        jQuery.post(ajaxurl, { action:'ans_delete_link_keys', nonce: ANS_NONCE, keywords:[kw] }, function(){ location.reload(); });
    }
    function deleteDupSingle(title) {
        if(!confirm('Delete copies of: '+title+'?')) return;
        jQuery.post(ajaxurl, { action:'ans_delete_dup_single', nonce: ANS_NONCE, title:title }, function(r){
            if(r.success){ alert(r.data); jQuery('#scan_dup_btn').click(); }
        });
    }

    jQuery(document).ready(function($) {
        // DELAY SLIDER
        $('#ans_scrape_delay').on('input', function(){ $('#delay_val').text(this.value + 's'); });

        function log(msg, type) {
            var cls = type==='err'?'lerr':type==='warn'?'lwarn':'';
            $('#logs').prepend('<div class="ali '+cls+'"><span style="color:#475569;">'+new Date().toLocaleTimeString()+'</span> '+escapeHtml(msg)+'</div>');
        }
        function dupLog(msg) { $('#dup_logs').prepend('<div class="ali"><span style="color:#475569;">'+new Date().toLocaleTimeString()+'</span> '+escapeHtml(msg)+'</div>'); }
        function escapeHtml(value) {
            return String(value || '').replace(/[&<>"']/g, function(ch) {
                return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[ch];
            });
        }
        function cleanReason(reason) {
            return String(reason || 'No reason returned').replace(/\s+/g, ' ').trim();
        }
        function resetResultDetails() {
            resultDetails = { fail: [], skip: [] };
            activeResultType = 'fail';
            $('#result_panel').hide();
            $('#result_body').empty();
        }
        function recordResult(type, url, reason, retryable) {
            if(type !== 'fail' && type !== 'skip') return;
            var list = resultDetails[type];
            var key = String(url || '').trim() + '|' + cleanReason(reason);
            var existing = list.find(function(item) { return item.key === key; });
            if(existing) {
                existing.attempts += 1;
                existing.time = new Date().toLocaleTimeString();
                existing.retryable = existing.retryable || retryable !== false;
            } else {
                list.push({
                    key: key,
                    url: String(url || '').trim(),
                    reason: cleanReason(reason),
                    time: new Date().toLocaleTimeString(),
                    attempts: 1,
                    retryable: retryable !== false
                });
            }
            if($('#result_panel').is(':visible') && activeResultType === type) renderResultPanel(type);
        }
        function renderResultPanel(type) {
            activeResultType = type;
            var list = resultDetails[type] || [];
            var label = type === 'fail' ? 'Failed' : 'Skipped';
            var attempts = list.reduce(function(total, item) { return total + item.attempts; }, 0);
            var retryable = list.filter(function(item) { return item.retryable && item.url; }).length;
            $('#result_title').text(label + ' URLs');
            $('#result_meta').text(attempts + ' attempts, ' + list.length + ' unique URLs, ' + retryable + ' retryable.');
            $('#result_panel').show();
            $('#result_select_toggle').text('Select All');

            if(!list.length) {
                $('#result_body').html('<div class="result-empty">No '+label.toLowerCase()+' URLs captured yet.</div>');
                return;
            }

            var rows = list.map(function(item, idx) {
                var disabled = (!item.retryable || !item.url) ? ' disabled' : '';
                var action = item.retryable && item.url ? '<button type="button" class="mini-btn primary retry-one" data-result-idx="'+idx+'">Retry</button>' : '<span style="color:#64748b;">Not retryable</span>';
                return '<tr>' +
                    '<td><input type="checkbox" class="result-check" data-result-idx="'+idx+'"'+disabled+'></td>' +
                    '<td>'+(idx+1)+'</td>' +
                    '<td><a class="result-url" href="'+escapeHtml(item.url)+'" target="_blank" rel="noopener noreferrer">'+escapeHtml(item.url)+'</a></td>' +
                    '<td><span class="reason-pill">'+escapeHtml(item.reason)+'</span></td>' +
                    '<td>'+escapeHtml(item.time)+'</td>' +
                    '<td>'+item.attempts+'</td>' +
                    '<td>'+action+'</td>' +
                '</tr>';
            }).join('');

            $('#result_body').html('<table class="result-table"><thead><tr><th></th><th>#</th><th>Post URL</th><th>Reason</th><th>Last Seen</th><th>Attempts</th><th>Action</th></tr></thead><tbody>'+rows+'</tbody></table>');
        }
        function getResultUrls(type, mode, singleIdx) {
            var list = resultDetails[type] || [];
            if(mode === 'single') {
                var item = list[singleIdx];
                return item && item.retryable && item.url ? [item.url] : [];
            }
            if(mode === 'selected') {
                var urls = [];
                $('#result_body .result-check:checked').each(function() {
                    var item = list[$(this).data('result-idx')];
                    if(item && item.retryable && item.url) urls.push(item.url);
                });
                return urls;
            }
            return list.filter(function(item) { return item.retryable && item.url; }).map(function(item) { return item.url; });
        }
        function retryResultUrls(urls) {
            urls = Array.from(new Set((urls || []).filter(Boolean)));
            if(!urls.length) { log('No retryable URLs selected.','warn'); return; }
            $.post(ajaxurl, {action:'ans_retry_urls', nonce:ANS_NONCE, urls:urls}, function(r) {
                if(r.success) {
                    var msg = 'Retry queued: '+r.data.queued+' URL(s).';
                    if(r.data.filtered) msg += ' '+r.data.filtered+' filtered.';
                    if(!run) msg += ' Press START ENGINE to publish.';
                    log(msg);
                    if(run && r.data.queued) { totalQueue += parseInt(r.data.queued, 10) || 0; updateStats(); }
                    updateQ();
                } else {
                    var err = r.data && r.data.msg ? r.data.msg : 'Retry queue error.';
                    log(err, 'err');
                }
            });
        }
        var qualityHoldItems = [];
        function renderQualityHoldPanel() {
            $('#quality_hold_panel').show();
            $('#quality_hold_select_toggle').text('Select All');
            $('#quality_hold_count').text(qualityHoldItems.length);
            $('#quality_hold_meta').text(qualityHoldItems.length + ' URL(s) saved because structure/quality did not match.');

            if(!qualityHoldItems.length) {
                $('#quality_hold_body').html('<div class="result-empty">No review-later URLs saved.</div>');
                return;
            }

            var rows = qualityHoldItems.map(function(item, idx) {
                return '<tr>' +
                    '<td><input type="checkbox" class="quality-hold-check" data-review-idx="'+idx+'"></td>' +
                    '<td>'+(idx+1)+'</td>' +
                    '<td><a class="result-url" href="'+escapeHtml(item.url)+'" target="_blank" rel="noopener noreferrer">'+escapeHtml(item.url)+'</a></td>' +
                    '<td><span class="reason-pill">'+escapeHtml(item.reason || 'Quality/structure mismatch')+'</span><br><span style="color:#64748b;font-size:11px;">'+escapeHtml(item.type || 'quality')+'</span></td>' +
                    '<td>'+escapeHtml(item.last_seen || item.first_seen || '-')+'</td>' +
                    '<td>'+escapeHtml(item.attempts || 1)+'</td>' +
                    '<td><button type="button" class="mini-btn primary quality-hold-retry-one" data-review-idx="'+idx+'">Retry</button></td>' +
                '</tr>';
            }).join('');

            $('#quality_hold_body').html('<table class="result-table"><thead><tr><th></th><th>#</th><th>Post URL</th><th>Reason</th><th>Last Seen</th><th>Attempts</th><th>Action</th></tr></thead><tbody>'+rows+'</tbody></table>');
        }
        function loadQualityHold(showPanel) {
            $.post(ajaxurl, {action:'ans_quality_hold_list', nonce:ANS_NONCE}, function(r) {
                if(!r.success) return;
                qualityHoldItems = (r.data && r.data.items) ? r.data.items : [];
                $('#quality_hold_count').text((r.data && typeof r.data.count !== 'undefined') ? r.data.count : qualityHoldItems.length);
                if(showPanel || $('#quality_hold_panel').is(':visible')) renderQualityHoldPanel();
            });
        }
        function getQualityHoldUrls(mode, singleIdx) {
            if(mode === 'single') {
                var one = qualityHoldItems[singleIdx];
                return one && one.url ? [one.url] : [];
            }
            if(mode === 'selected') {
                var urls = [];
                $('#quality_hold_body .quality-hold-check:checked').each(function() {
                    var item = qualityHoldItems[$(this).data('review-idx')];
                    if(item && item.url) urls.push(item.url);
                });
                return urls;
            }
            return qualityHoldItems.filter(function(item) { return item && item.url; }).map(function(item) { return item.url; });
        }
        function retryQualityHold(urls, all) {
            urls = Array.from(new Set((urls || []).filter(Boolean)));
            if(!all && !urls.length) { log('No review-later URLs selected.','warn'); return; }
            $.post(ajaxurl, {action:'ans_quality_hold_retry', nonce:ANS_NONCE, urls:urls, all:all ? 1 : 0}, function(r) {
                if(r.success) {
                    log('Review-later queued: '+r.data.queued+' URL(s).');
                    updateQ();
                    loadQualityHold(true);
                } else {
                    log(cleanReason(r.data || 'Review-later retry failed.'), 'err');
                }
            });
        }
        function deleteQualityHold(urls) {
            urls = Array.from(new Set((urls || []).filter(Boolean)));
            if(!urls.length) { log('No review-later URLs selected.','warn'); return; }
            $.post(ajaxurl, {action:'ans_quality_hold_delete', nonce:ANS_NONCE, urls:urls}, function(r) {
                if(r.success) {
                    log('Removed review-later URL(s).');
                    loadQualityHold(true);
                } else {
                    log(cleanReason(r.data || 'Review-later delete failed.'), 'err');
                }
            });
        }
        function updateQ() { $.post(ajaxurl, {action:'ans_count', nonce:ANS_NONCE}, function(r){ $('#q_count').text(r.data); }); }
        function updateStats() {
            $('#stat_success').text(stats.success);
            $('#stat_fail').text(stats.fail);
            $('#stat_skip').text(stats.skip);
            if(stats.times.length > 0) {
                var avg = (stats.times.reduce((a,b)=>a+b,0)/stats.times.length/1000).toFixed(1);
                $('#stat_speed').text(avg + 's/post');
            }
            if(totalQueue > 0) {
                var done = stats.success + stats.skip + stats.fail;
                var pct  = Math.round((done / totalQueue) * 100);
                $('#prog_fill').css('width', pct + '%');
                $('#prog_text').text(done + ' done of ' + totalQueue + ' (' + pct + '%)');
            }
        }

        updateQ();
        loadQualityHold(false);

        $('.stat-click').click(function(){
            var type = $(this).data('result-type');
            if(type) renderResultPanel(type);
        });
        $('#result_close').click(function(){ $('#result_panel').hide(); });
        $('#result_select_toggle').click(function(){
            var checks = $('#result_body .result-check:not(:disabled)');
            var shouldCheck = checks.filter(':checked').length !== checks.length;
            checks.prop('checked', shouldCheck);
            $(this).text(shouldCheck ? 'Clear Selection' : 'Select All');
        });
        $('#result_retry_all').click(function(){
            retryResultUrls(getResultUrls(activeResultType, 'all'));
        });
        $('#result_retry_selected').click(function(){
            retryResultUrls(getResultUrls(activeResultType, 'selected'));
        });
        $('#result_body').on('click', '.retry-one', function(){
            retryResultUrls(getResultUrls(activeResultType, 'single', $(this).data('result-idx')));
        });
        $('#quality_hold_btn').click(function(){ loadQualityHold(true); });
        $('#quality_hold_close').click(function(){ $('#quality_hold_panel').hide(); });
        $('#quality_hold_select_toggle').click(function(){
            var checks = $('#quality_hold_body .quality-hold-check');
            var shouldCheck = checks.filter(':checked').length !== checks.length;
            checks.prop('checked', shouldCheck);
            $(this).text(shouldCheck ? 'Clear Selection' : 'Select All');
        });
        $('#quality_hold_retry_all').click(function(){ retryQualityHold([], true); });
        $('#quality_hold_retry_selected').click(function(){ retryQualityHold(getQualityHoldUrls('selected'), false); });
        $('#quality_hold_delete_selected').click(function(){ deleteQualityHold(getQualityHoldUrls('selected')); });
        $('#quality_hold_body').on('click', '.quality-hold-retry-one', function(){
            retryQualityHold(getQualityHoldUrls('single', $(this).data('review-idx')), false);
        });

        // SAVE CONFIG
        $('#save_btn').click(function(){
            $.post(ajaxurl, { action:'ans_save', nonce:ANS_NONCE, lang:$('#ans_target_lang').val(), status:$('#ans_post_status').val(), img:$('#ans_import_img').val(), sitemap:$('#ans_sitemap_url').val(), title:$('#ans_title_sel').val(), body:$('#ans_body_sel').val(), manual_category:$('#ans_manual_category').val(), my_brand:$('#ans_my_brand').val(), delay:$('#ans_scrape_delay').val() }, function(r){ if(r.success) log('Configuration saved.'); else log('Save error.','err'); });
        });

        // CLEAN QUEUE
        $('#clean_queue_btn').click(function(){
            var btn=$(this); btn.text('Cleaning...').prop('disabled',true);
            $.post(ajaxurl, {action:'ans_clean_queue', nonce:ANS_NONCE}, function(r){
                if(r.success) { log('✅ '+r.data); updateQ(); }
                btn.text('🧹 Clean Queue').prop('disabled',false);
            });
        });

        // FETCH VIA BROWSER
        $('#fetch_btn').click(function(){
            var su = $('#ans_sitemap_url').val(); if(!su){alert('Enter sitemap URL.');return;}
            log('Fetching sitemap...');
            fetch('https://api.codetabs.com/v1/proxy?quest='+encodeURIComponent(su))
                .then(r=>{ if(!r.ok) throw 'blocked'; return r.text(); })
                .then(d=>parseAndQueue(d,'CodeTabs'))
                .catch(()=>{
                    log('CodeTabs failed. Trying Jina...','warn');
                    fetch('https://r.jina.ai/'+su,{headers:{'X-Return-Format':'html'}})
                        .then(r=>r.text()).then(d=>parseAndQueue(d,'Jina'))
                        .catch(()=>log('Fetch failed. Use Manual Paste.','err'));
                });
        });

        // PARSE & QUEUE — with media filter
        function parseAndQueue(data, source) {
            log('Parsing from '+source+'...');
            var urls=[], skipped=0;
            var rx = /(https?:\/\/[^\s"<>\)]+)/g, m;
            while((m=rx.exec(data))!==null){
                var u=m[1];
                if(u.includes('google')||u.includes('.xml')||u.includes('w3.org')) continue;
                if(isMediaUrl(u)||u.includes('/wp-content/uploads/')){ skipped++; continue; }
                urls.push(u);
            }
            if(skipped>0) log('🧹 '+skipped+' media URLs filtered.','warn');
            if(urls.length===0){ log('No valid URLs found.','err'); return; }
            $.post(ajaxurl, {action:'ans_save_queue', nonce:ANS_NONCE, urls:urls}, function(r){
                if(r.success){ log(r.data); totalQueue=urls.length; updateQ(); $('#progress_wrap').show(); }
                else log('Queue save error.','err');
            });
        }

        // MANUAL PARSE
        $('#manual_parse_btn').click(function(){
            var d=$('#manual_sitemap_data').val(); if(!d){alert('Paste URLs first.');return;}
            parseAndQueue(d,'Manual');
        });

        // CLEAR LOGS
        $('#clear_btn').click(function(){ $.post(ajaxurl,{action:'ans_clear', nonce:ANS_NONCE},function(){ $('#logs').html('<div class="ali">Logs cleared.</div>'); updateQ(); }); });

        // ENGINE
        var run=false;
        $('#start_btn').click(function(){
            if(run) return;
            if($('#ans_target_lang').val()==='select'){alert('Select language!');return;}
            run=true; stats={success:0,fail:0,skip:0,times:[]};
            resetResultDetails();
            $(this).css('opacity','0.5'); $('#stop_btn').css('opacity','1').prop('disabled',false);
            $('#progress_wrap').show();
            log('Engine Started V315.1...');
            $.post(ajaxurl, {action:'ans_count', nonce:ANS_NONCE}, function(r){
                totalQueue = parseInt(r.data, 10) || totalQueue || 0;
                $('#q_count').text(totalQueue);
                updateStats();
                processNext();
            }).fail(function(){
                processNext();
            });
        });
        $('#stop_btn').click(function(){
            run=false; $(this).css('opacity','0.5').prop('disabled',true); $('#start_btn').css('opacity','1');
            log('Engine Stopped.','err');
        });

        async function processNext() {
            if(!run) return;
            $.post(ajaxurl, {action:'ans_get_next_task', nonce:ANS_NONCE}, function(res){
                if(!res.success){ log(res.data,'err'); run=false; $('#start_btn').css('opacity','1'); $('#stop_btn').css('opacity','0.5'); return; }
                var url = res.data;
                // JS-side media check
                if(isMediaUrl(url)||url.includes('/wp-content/uploads/')){
                    log('⏭ Skipped media: '+url,'warn');
                    $.post(ajaxurl,{action:'ans_skip_url', nonce:ANS_NONCE},function(){ recordResult('skip', url, 'Media URL / upload URL', false); stats.skip++; updateQ(); updateStats(); if(run) setTimeout(processNext,500); });
                    return;
                }
                log('Processing: '+url+'...');
                var t0 = Date.now();
                $.ajax({
                    url: ajaxurl, type:'POST', timeout:120000,
                    data:{ action:'ans_process_content', nonce:ANS_NONCE, url:url, lang:$('#ans_target_lang').val(), status:$('#ans_post_status').val(), img_opt:$('#ans_import_img').val(), body_sel:$('#ans_body_sel').val(), title_sel:$('#ans_title_sel').val() },
                    success:function(r){
                        var elapsed = Date.now()-t0;
                        if(r.success){
                            log(r.data.msg); stats.success++; stats.times.push(elapsed);
                        } else {
                            var reason = cleanReason(r.data);
                            if(r.data&&(r.data.includes('Duplicate')||r.data.includes('Skipped')||r.data.includes('exists'))){ log(r.data,'warn'); recordResult('skip', url, reason, true); stats.skip++; }
                            else if(r.data&&r.data.includes('3 failed')){ log(r.data,'err'); recordResult('skip', url, reason, true); stats.skip++; }
                            else { log(r.data+' (attempt logged)','err'); recordResult('fail', url, reason, true); stats.fail++; }
                            if(reason.indexOf('structure changed') !== -1 || reason.indexOf('block order changed') !== -1 || reason.indexOf('translation incomplete') !== -1 || reason.indexOf('paragraph-heading structure') !== -1) {
                                loadQualityHold(false);
                            }
                        }
                        updateQ(); updateStats();
                        var delay = parseInt($('#ans_scrape_delay').val())*1000;
                        var jitter = Math.floor(Math.random()*2000);
                        if(run) setTimeout(processNext, delay+jitter);
                    },
                    error:function(xhr,st){ log('Server timeout. Waiting...','err'); recordResult('fail', url, 'Server timeout / AJAX error: '+st, true); stats.fail++; updateStats(); if(run) setTimeout(processNext,15000); }
                });
            }).fail(function(){ log('Connection lost. Retrying...','err'); if(run) setTimeout(processNext,10000); });
        }

        // ---- TOGGLE LINKING ----
        $('#btn-toggle-link').click(function(){
            var btn=$(this); btn.text('Updating...').prop('disabled',true);
            $.post(ajaxurl,{action:'ans_toggle_linking',nonce:ANS_NONCE},function(r){
                if(r.success){
                    if(r.data==='yes'){ $('#status-text').html('<span style="color:#22c55e;">● Running</span>'); btn.text('PAUSE LINKING').css('background','#f59e0b'); }
                    else { $('#status-text').html('<span style="color:#f59e0b;">⏸ Paused</span>'); btn.text('RESUME LINKING').css('background','#22c55e'); }
                }
                btn.prop('disabled',false);
            });
        });

        // ---- LINK SCAN ----
        function runBatchScan(offset){
            $.post(ajaxurl,{action:'ans_link_scan',nonce:ANS_NONCE,offset:offset},function(res){
                if(res.success){
                    var t=res.data.total, n=res.data.next_offset;
                    var pct=Math.min(Math.round((n/t)*100),100);
                    $('#scan-bar').css('width',pct+'%'); $('#scan-text').text('Indexing 3+ word anchors '+pct+'% ('+n+'/'+t+') - '+(res.data.rules||0)+' rules');
                    if(n<t) runBatchScan(n);
                    else { $('#scan-text').text('Done. 3+ word graph ready. Reloading...'); setTimeout(()=>location.reload(),1500); }
                }
            });
        }
        $('#btn-link-scan').click(function(){ reportOffset=0; $(this).prop('disabled',true); $('.pbwrap').show(); runBatchScan(0); });

        // ---- LINK REPORT ----
        $('#btn-link-report, #btn-load-more').click(function(){
            var btn=$(this); btn.text('Loading...');
            if(btn.attr('id')==='btn-link-report') reportOffset=0;
            $.post(ajaxurl,{action:'ans_link_report',nonce:ANS_NONCE,offset:reportOffset},function(res){
                if(res.success){
                    $('#report-body').html(res.data.html);
                    reportOffset=res.data.next_offset;
                    $('#range-display').text('Posts: '+res.data.current_range);
                    $('#btn-load-more').text('Check Next 50 Posts');
                    $('#btn-link-report').text('Check 3+ Word Links');
                    if(btn.attr('id')==='btn-link-report') openSubTab({currentTarget:$('.stab')[1]},'st-report');
                }
            });
        });

        // SELECT ALL IN REPORT
        $('#btn-sel-all').click(function(){
            var all=$('#report-body .cb-row');
            var checked=all.filter(':checked').length===all.length;
            all.prop('checked',!checked);
            $(this).text(!checked?'Deselect All':'Select All');
        });

        // APPLY LINKS PERMANENTLY
        $('#btn-apply-links').click(function(){
            var items=[];
            $('#report-body .cb-row:checked').each(function(){
                items.push({post_id:$(this).data('post-id'),keyword:$(this).data('keyword'),url:$(this).data('url'),title:$(this).data('title')});
            });
            if(!items.length){alert('Select 3+ word links from Link Report tab first!');return;}
            if(!confirm('Apply '+items.length+' 3+ word internal links permanently?')) return;
            var btn=$(this); btn.text('Applying...').prop('disabled',true); $('#apply-status').text('');
            $.post(ajaxurl,{action:'ans_apply_links',nonce:ANS_NONCE,items:items},function(r){
                $('#apply-status').text(r.success?'✔ '+r.data:'✘ '+r.data).css('color',r.success?'#22c55e':'#ef4444');
                btn.text('Apply Permanently').prop('disabled',false);
            });
        });

        function runApplyAllBatch(offset, totalApplied, totalSkipped){
            $.post(ajaxurl,{action:'ans_apply_all_links',nonce:ANS_NONCE,offset:offset},function(r){
                if(!r.success){
                    $('#apply-status').text(r.data || 'Auto apply failed.').css('color','#ef4444');
                    $('#btn-apply-all-links').text('Auto Apply All').prop('disabled',false);
                    return;
                }
                var d=r.data;
                totalApplied += parseInt(d.applied,10)||0;
                var totalRelated = (parseInt($('#apply-status').data('related'),10)||0) + (parseInt(d.related,10)||0);
                $('#apply-status').data('related', totalRelated);
                totalSkipped += parseInt(d.skipped,10)||0;
                var pct=d.total ? Math.min(Math.round((d.processed/d.total)*100),100) : 100;
                $('#apply-status').text('Auto applying '+pct+'% - phrase links '+totalApplied+', related titles '+totalRelated+', skipped '+totalSkipped).css('color','#22c55e');
                if(!d.done) runApplyAllBatch(d.next_offset,totalApplied,totalSkipped);
                else $('#btn-apply-all-links').text('Auto Apply All').prop('disabled',false);
            });
        }

        $('#btn-apply-all-links').click(function(){
            if(!confirm('Auto apply 3+ word links and exact related-article title links across all published posts?')) return;
            $(this).text('Auto Applying...').prop('disabled',true);
            $('#apply-status').data('related',0).text('Starting all-post interlinking...').css('color','#22c55e');
            runApplyAllBatch(0,0,0);
        });

        $('#btn-link-clear').click(function(){ if(confirm('Clear all link data?')) $.post(ajaxurl,{action:'ans_clear_links',nonce:ANS_NONCE},function(){location.reload();}); });

        // ---- ORPHAN FINDER — BATCHED ----
        function runOrphanBatch(offset){
            $('#orphan-pb-wrap').show();
            $.post(ajaxurl,{action:'ans_find_orphans',nonce:ANS_NONCE,offset:offset},function(r){
                if(!r.success) return;
                var d=r.data;
                if(!d.done){
                    var pct=Math.round((d.scanned/d.total)*100);
                    $('#orphan-bar').css('width',pct+'%');
                    $('#orphan-status').text('Scanning... '+d.scanned+'/'+d.total);
                    runOrphanBatch(d.next_offset);
                } else {
                    $('#orphan-pb-wrap').hide();
                    $('#btn-find-orphans').text('Found '+d.count+' Orphans — Rescan').prop('disabled',false);
                    $('#orphan-status').text(d.count+' orphan posts found.');
                    if(!d.count){ $('#orphan-body').html('<tr><td colspan="2" style="text-align:center;padding:20px;color:#22c55e;">No orphan posts! All posts are linked.</td></tr>'); return; }
                    var html='';
                    d.orphans.forEach(function(o){ html+='<tr><td><a href="'+escapeHtml(o.url)+'" target="_blank" rel="noopener noreferrer" style="color:#cbd5e1;">'+escapeHtml(o.title)+'</a></td><td style="font-size:11px;color:#64748b;">'+escapeHtml(o.url)+'</td></tr>'; });
                    $('#orphan-body').html(html);
                }
            });
        }
        $('#btn-find-orphans').click(function(){
            $(this).text('Scanning...').prop('disabled',true);
            $('#orphan-body').html('<tr><td colspan="2" style="text-align:center;padding:20px;color:var(--muted);">Scanning...</td></tr>');
            orphanOffset=0;
            runOrphanBatch(0);
        });

        // ---- DUPLICATE CLEANER ----
        var dupIds=[];
        $('#scan_dup_btn').click(function(){
            $(this).text('Scanning...').prop('disabled',true);
            $('#dup_result_area').hide().html(''); $('#bulk_actions_area').hide();
            dupLog('Scanning for duplicates...');
            $.post(ajaxurl,{action:'ans_scan_duplicates',nonce:ANS_NONCE},function(r){
                if(r.success&&r.data.count>0){
                    dupLog('Found '+r.data.count+' duplicate sets ('+r.data.total_dups+' posts to remove).');
                    var html='<div style="text-align:center;color:#f59e0b;font-weight:bold;padding:15px;border-bottom:1px solid #334155;">Found '+r.data.count+' sets — '+r.data.total_dups+' posts to clean</div>';
                    r.data.preview.forEach(function(it){
                        html+='<div class="ditem"><span class="dtitle">'+escapeHtml(it.title)+'<span class="dcnt">'+escapeHtml(it.count)+'x</span></span><button type="button" class="ddel dup-single-del" data-title="'+escapeHtml(it.title)+'">Delete Copies</button></div>';
                    });
                    if(r.data.count>20) html+='<div style="padding:10px;text-align:center;color:var(--muted);font-size:12px;">...and '+(r.data.count-20)+' more sets.</div>';
                    $('#dup_result_area').html(html).slideDown();
                    $('#confirm_del_btn').text('DELETE ALL '+r.data.total_dups+' DUPLICATES');
                    $('#bulk_actions_area').show();
                    dupIds=r.data.ids_to_delete;
                        jQuery(document).trigger('ans_dup_scanned', [r.data]);
                } else { dupLog('No duplicates found! DB is clean.'); $('#dup_result_area').html('<div style="color:#22c55e;padding:20px;text-align:center;font-weight:bold;">No duplicates found!</div>').slideDown(); }
                $('#scan_dup_btn').text('SCAN AGAIN').prop('disabled',false);
            });
        });

        $('#dup_result_area').on('click', '.dup-single-del', function(){
            deleteDupSingle($(this).data('title'));
        });

        // BATCH DELETE DUPLICATES
        $('#confirm_del_btn').click(function(){
            if(!dupIds.length) return;
            var force=$('#perm_delete_chk').is(':checked')?'1':'0';
            var label=force==='1'?'PERMANENTLY DELETE':'TRASH';
            if(!confirm('WARNING: '+label+' '+dupIds.length+' duplicate posts?')) return;
            $(this).prop('disabled',true);
            $('#del_progress').show();
            var remaining=[...dupIds], total=dupIds.length, deleted=0;

            function deleteBatch(){
                if(!remaining.length){ dupLog('Done! Deleted '+deleted+' posts.'); $('#bulk_actions_area').hide(); $('#scan_dup_btn').text('SCAN AGAIN').prop('disabled',false); return; }
                $.post(ajaxurl,{action:'ans_delete_selected',nonce:ANS_NONCE,ids:remaining,force:force},function(r){
                    if(r.success){
                        deleted+=r.data.deleted;
                        remaining=r.data.remaining;
                        var pct=Math.round((deleted/total)*100);
                        $('#del_prog_fill').css('width',pct+'%');
                        $('#del_prog_text').text(deleted+'/'+total+' deleted ('+pct+'%)');
                        dupLog(r.data.msg);
                        if(remaining.length) setTimeout(deleteBatch,500);
                        else { dupLog('All duplicates removed!'); $('#dup_result_area').html('<div style="padding:30px;text-align:center;color:#22c55e;font-size:18px;font-weight:bold;">✔ All Duplicates Deleted!</div>').show(); $('#bulk_actions_area').hide(); $('#scan_dup_btn').text('SCAN AGAIN').prop('disabled',false); }
                    }
                });
            }
            deleteBatch();
        });

        // BULK DELETE RULES
        $(document).on('change','.cb-row,.cb-all',function(){
            var t=$(this).closest('table'), cnt=t.find('.cb-row:checked').length;
            t.find('.cb-all').prop('checked',cnt===t.find('.cb-row').length&&cnt>0);
            t.closest('.ftblc').find('.bulk-del-btn').prop('disabled',cnt===0).text(cnt>0?'Delete Selected ('+cnt+')':'Delete Selected');
        });
        $('.bulk-del-btn').click(function(){
            var sel=[]; $(this).closest('.ftblc').find('.cb-row:checked').each(function(){ sel.push($(this).val()); });
            if(!sel.length||!confirm('Remove '+sel.length+' rules?')) return;
            $.post(ajaxurl,{action:'ans_delete_link_keys',nonce:ANS_NONCE,keywords:sel},function(){ location.reload(); });
        });


        // Toggle Mode for Content Purity
        window.toggleMode = function() {
            var chk = document.getElementById('perm_delete_chk');
            var track = document.getElementById('toggle_track');
            var thumb = document.getElementById('toggle_thumb');
            var lbl = document.getElementById('mode_label');
            var sub = document.getElementById('mode_sub');
            chk.checked = !chk.checked;
            if(chk.checked) {
                track.style.background = '#ef4444';
                thumb.style.marginLeft = '22px';
                lbl.textContent = 'Permanent Delete';
                sub.textContent = 'Cannot be undone';
            } else {
                track.style.background = '#334155';
                thumb.style.marginLeft = '2px';
                lbl.textContent = 'Move to Trash';
                sub.textContent = 'Recoverable';
            }
        };

        // Update dup stats after scan
        jQuery(document).on('ans_dup_scanned', function(e, data) {
            jQuery('#dup_stat_sets').text(data.count || '0');
            jQuery('#dup_stat_posts').text(data.total_dups || '0');
            jQuery('#dup_scan_status').text('Last scan: ' + new Date().toLocaleTimeString());
        });

    }); // end ready
    </script>
    <?php
}
?>
