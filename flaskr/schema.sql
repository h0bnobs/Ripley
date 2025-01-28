DROP TABLE IF EXISTS config;

CREATE TABLE config (
  targets TEXT,
  nmap_parameters TEXT,
  config_filepath TEXT,
  ffuf_delay TEXT,
  extra_commands_file TEXT,
  ffuf_subdomain_wordlist TEXT,
  ffuf_webpage_wordlist TEXT,
  disable_chatgpt_api TEXT
);