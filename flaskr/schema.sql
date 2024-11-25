DROP TABLE IF EXISTS config;

CREATE TABLE config (
  single_target Text,
  multiple_targets TEXT,
  targets_file TEXT,
  nmap_parameters TEXT,
  config_filepath TEXT,
  extra_commands TEXT
);

-- "single_target": "",
--     "multiple_targets": "",
--     "targets_file": "",
--     "nmap_parameters": ""