# Engineered Features Module

Provides deterministic extraction of 22 frozen URL-only features:
- Length variables: `url_length`, `hostname_length`, `path_length`, `query_length`, `path_depth`, `subdomain_depth`
- Binary flags: `has_query`, `has_port`, `is_root_path`, `is_ip`, `is_private_suffix`, `has_www`, `is_https`, `is_missing_scheme`, `has_punycode`
- Character counts & ratios: `digit_count`, `digit_ratio`, `hyphen_count`, `dot_count`, `special_char_count`, `percent_encoded_count`, `char_entropy`

All feature extraction is 100% deterministic, operate strictly on the URL string, and require zero external DNS or network access.
