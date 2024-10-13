# Diary

### Thursday 10th October
10/10/24 04:30pm
- Decided that there is going to be a difference between the cli and gui version.
- Added run_commands.py and utils.py in the scripts directory and fixed http-get-improved.
- Decided that the cli version is going to be run through a config.json file! No -u or -i or whatever, only a config file.
- Spent time implementing this, doing things including but not limited to:
  - Fixing the methods that run nmap, showmount and smbclient.
  - Adding in the logic that parses the config file.
  - Adding in the logic that determines if there are going to be multiple targets, then runs the tool against those targets.
- Refactored.

### Sunday 13th October
13/10/24 05:20pm
- Renamed read_config_file to parse_config_file & updated the usage string on the banner.
- Decided to change how the config is going to work in regard to the target(s).
  - Previously, There used to be one config option/setting where the user would input their target/targets. Now there are 3 different options:
    - "single_target"
    - "multiple_targets"
    - "targets_file" 
  - The user must use only 1 of these 3 options. Please see [the config settings](config_settings.md). 
  - If they want to use the tool against only one target, they fill out "single_target".
  - If they want to list targets they use "multiple_targets"
  - If they want to use a target file they use "targets_file".
- So I added logic to implement this in main.
- Renamed and changed the logic of multiple_targets and single_target to run_on_multiple_targets and run_on_single_target.