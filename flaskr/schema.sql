-- CREATE TABLE IF NOT EXISTS current_config
-- (
--     full_path TEXT,
--     filename  TEXT
-- );

CREATE TABLE IF NOT EXISTS extra_commands
(
    scan_num       INT
        constraint fk
            references scan_results
            on delete cascade,
    command        TEXT,
    command_output TEXT
);

CREATE TABLE IF NOT EXISTS scan_results
(
    target            TEXT not null,
    host_output       TEXT,
    nmap_output       TEXT,
    smbclient_output  TEXT,
    ftp_result        TEXT,
    screenshot        TEXT,
    robots_output     TEXT,
    scan_start_time   TIMESTAMP default CURRENT_TIMESTAMP,
    ai_advice         TEXT,
    scan_num          integer
        constraint scan_results_pk
            primary key autoincrement,
    subdomains_found  TEXT,
    dns_recon_output  TEXT,
    webpages_found    TEXT,
    wpscan_output     TEXT,
    metasploit_output TEXT,
    security_headers  TEXT
);

CREATE TABLE IF NOT EXISTS config
(
    targets                 TEXT,
    ports_to_scan           TEXT,
    scan_type               TEXT,
    aggressive_scan         TEXT,
    scan_speed              TEXT,
    os_detection            TEXT,
    host_timeout            TEXT,
    ping_hosts              TEXT,
    ping_method             TEXT,
    config_filepath         TEXT,
    ffuf_delay              TEXT,
    ffuf_subdomain_wordlist TEXT,
    ffuf_webpage_wordlist   TEXT,
    disable_chatgpt_api     TEXT,
    enable_ffuf             TEXT,
    verbose                 TEXT,
    openai_api_key          TEXT,
    extra_commands          TEXT,
    chatgpt_model           TEXT,
    ffuf_redirect           TEXT,
    speed                   TEXT
);
