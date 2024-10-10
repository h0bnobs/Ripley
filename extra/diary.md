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