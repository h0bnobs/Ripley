# Logbook

### Thursday 10th October

10/10/24 04:30pm

- Decided that there is going to be a difference between the cli and gui version.
- Added run_commands.py and utils.py in the scripts directory and fixed http-get-improved.
- Decided that the cli version is going to be run through a config.json file! No -u or -i or whatever, only a config
  file.
- Spent time implementing this, doing things including but not limited to:
    - Fixing the methods that run nmap, showmount and smbclient.
    - Adding in the logic that parses the config file.
    - Adding in the logic that determines if there are going to be multiple targets, then runs the tool against those
      targets.
- Refactored.

### Sunday 13th October

13/10/24 05:20pm

- Renamed read_config_file to parse_config_file & updated the usage string on the banner.
- Decided to change how the config is going to work in regard to the target(s).
    - Previously, There used to be one config option/setting where the user would input their target/targets. Now there
      are 3 different options:
        - "single_target"
        - "multiple_targets"
        - "targets_file"
    - The user must use only 1 of these 3 options. Please see [the config settings](config_settings.md).
    - If they want to use the tool against only one target, they fill out "single_target".
    - If they want to list targets they use "multiple_targets"
    - If they want to use a target file they use "targets_file".
- So I added logic to implement this in main.
- Renamed and changed the logic of multiple_targets and single_target to run_on_multiple_targets and
  run_on_single_target.

### Monday 14th October

14/10/24 05:20pm

- Changed the method names in [run_commands.py](../scripts/run_commands.py) so that they were a bit more descriptive and
  clear.
- Added run_command_with_output_after in [run_commands.py](../scripts/run_commands.py)
- Utilised run_command_with_output_after in run_smbclient

### Thursday 17th October

17/10/24 03:00pm

- Implemented early version of the Flask GUI
    - Added [flaskr](../flaskr) directory and all the contents.
    - This is a start for the gui, and lots more work needs to go into it.

### Tuesday 22nd October

22/10/24 03:00pm

- More work on the GUI. [Screenshot](screenshots/22-10-24.png)
- Most changes were
  in [run_tool_for_gui.py](../run_tool_for_gui.py), [run_commands.py](../scripts/run_commands.py), [ripley_cli.py](../ripley_cli.py)
  and the [index](../flaskr/templates/general_settings.html).
- Added the following tools/checks:
    - Get the contents of robots.txt file.
    - Use the dnsrecon tool to get subdomains.
    - Get a screenshot of the webpage.
- Fixed run_smbclient and run_ftp in [ripley_cli.py](../ripley_cli.py)
- Changed return types for some methods in [run_commands.py](../scripts/run_commands.py)

### Thursday 24th October

24/10/24 03:20pm

- More work on the GUI. [Screenshot 1](screenshots/24-10-24_01.png) & [Screenshot 2](screenshots/24-10-24_02.png)
    - Added collapsible report elements so that it's a bit more organised.
    -
  Added [multiple_targets_result.html](../flaskr/templates/multiple_targets_result.html) & [single_target_result.html](../flaskr/templates/single_target_result.html)
  for organised results per the scan.
    - Had to rework [the init file](../flaskr/__init__.py) & [run_tool_for_gui](../run_tool_for_gui.py) so that the scan
      results are handled and displayed correctly!

### Thursday 7th November

07/11/24 11:20am

- Added [chatgpt_call.py](../scripts/chatgpt_call.py) that takes the output of the scan and sends it to the OpenAI API
  to get AI generated advice/insights.
- Added logic for the database.
- Added logic for multiple and single targets in [init](../flaskr/__init__.py).

### Sunday 10th November

10/11/24 01:40pm

- Currently, for a scan against 5 targets, it costs $0.40 for a call to gpt4.0, so I have switched to 3.5 for testing.
- Added Concurrency in [the multiple targets gui script](../run_tool_for_gui.py).
    - I ran some tests so before when scanning 2 targets it took 82 seconds, and now it takes 43.
    - For a scan against 5 targets it took 172 seconds and now takes 43 seconds.
- Added some [logic](../flaskr/static/js/index.js) for the [homepage](../flaskr/templates/general_settings.html) so that
  if the user is using a targets file, some of the contents are displayed and they can also view their entire targets
  file in the browser.
- Also added [the previous scans page](../flaskr/templates/previous_scans.html) that uses the db to display the previous
  scans.
    - Currently, it is set up for single scans only. I need to think of a way to preperly display scans that were
      against more than 1 target.
- Added a back button for all results pages.

### Sunday 17th November

17/11/24 05:20pm

- Added `ffuf` subdomain enumeration.
- Rewrote the cli version to incorporate all the new changes added to [run_tool_for_gui.py](../run_tool_for_gui.py).
- Added some extra helper methods to [utils.py](../scripts/utils.py).
- Reworded the AI prompt.

### Monday 25th November

25/11/24 11:40am

- Added `ffuf` for webpage/dictionary enumeration.
- Started work on a feature where the user can add their own commands to the tool.
- Fixed the [previous scans page](../templates/previous_scan_single_target.html) so that the user can now fully view any
  previous scan.

### Saturday 30th November

30/11/24 12:40pm

- Added the ability for the user to add their own commands to the tool, for single scans only.
- Reworked the concurrency code so that ffuf subdomain and webpage enumeration is run at the same time as the group of
  all of the other concurrent scans.

### Tuesday 3rd December

03/12/24 05:10pm

- Added the add commands tool for multiple scans.
- Added wpscan to the webpage ffuf scan thread pool.
- Integrated 'ffuf_delay' into the config and the ffuf methods.
- Added the ability to sort previous scans by scan_num.

### Sunday 22nd December

22/12/24 03:30pm

- Added the ability to upload config files.

### Wednesday 1st January

01/01/25 03:15pm

- Added the ability to remove added commands.
- The whole `added commands` feature is now reliant on the `extra_commands_file` in the config. The extra_commands.txt
  file from `flaskr/static/temp` is now deprecated and gone.

### Monday 6th January

06/01/25 03:50pm

- Nice QOL changes to the GUI including
    - Custom error pages can be created. The custom part is just a string error message, and a redirect link.
    - If single_target and targets_file are both populated in the config, the user is now told to only use one.
    - The current working directory is displayed on the homepage, and there is a toggleable button to show/hide the
      relevant files in that directory.
    - The custom error page has been implemented when the user tries to add extra commands, when the extra_commands_file
      setting in the config isn't populated.

### Thursday 16th January

16/01/25 12:40pm

- Issues and todos ticked off including:
    - The config is no longer hardcoded in init.py. It is now fully dynamic with a new table in the db.
    - Robots.txt is no longer scanned twice on a single target.
    - Extra commands feature has been cleaned up with proper errors and checks.
- The user can now fully edit commands in the extra commands feature.
- The config feature (like mentioned before) is now more robust and no longer hardcoded. When a user doesn't have an
  active config, they are prompted to select one.
- Started experimenting with colours for the GUI.
- The user can sort previous scans by target and or date.
- Fixed the logic in the get_db method.
- Added more robust checks for the extra_commands code in `run_tool_for_gui`, along with the chatgpt api call.
- Reworked `is_target_webpage` in `ripley_cli`

### Tuesday 28th January

28/01/25 03:40pm

- Removed "single_target", "multiple_targets" and "targets_file" from the config table in the database, and replaced
  them with "targets".
    - The user now only has to input their target(s) into a new text area above the config settings.
    - This is in the format of `target1, target2, target3` where `targets` can be and IPv4 address, a domain name, a
      CIDR range or two IPv4 addresses, seperated by a dash, eg `192.168.1.1-192.168.1.10`.
    - When you update the config, the targets are simply saved to "targets" in the config table, then when the tool is
      run, this string is just parsed to the scope of the format described above.
- Added some more checks for the extra commands feature.
- Added custom wordlists for ffuf subdomain and webpage enumeration. New options in the config as
  `ffuf_subdomain_wordlist` and `ffuf_webpage_wordlist`.
- Added an opt-out feature for the chatgpt api call. New option in the config as `disable_chatgpt_api`.
- Changed the style of the GUI. Needs revising. [Screenshot](screenshots/28-01-25.png)
- The homepage notifies the user if the config/targets need saving.

### Friday 7th February

07/02/25 11:00am

- Migrated to using the `session` variable for most pages and endpoints.
- Changed the homepage to `general_settings`
    - Started changing the way that settings are inputted by the user by adding `general_settings`,
      `host_discovery_settings`, `port_scanning_settings` and `advanced_settings`.
- Added the helper methods `reload_homepage` and `update_config_json_file`.
- Added the ability to upload targets files.

### Sunday 9th February

09/02/25 03:20pm

- Added `scan_type`, `aggressive_scan`, `scan_speed` and `os_detection` to the config and the `port_scanning_settings`
  page.
- Changed the `update_config` logic.
- Added `default_config.json` and fixed `chatgpt_call.py`.

### Friday 14th February

14/02/25 01:40pm

- Refactored `ripley_clip.py`, `run_tool_for_gui.py` and added `scanner_tools.py`.
- added `host_timeout`, `ping_hosts` and `ping_method` as options.

### Tuesday 25th February

25/02/25 10:30am

- Added `ai insights` and `ffuf` options to `advanced_settings`.
- Added wordlist uploads for `ffuf`
- Added `add_commands` page to the left hand nav bar.
- Added `select_commands_file` for when there is no commands file in the config.

### Tuesday 25th February

25/02/25 04:40pm

- Improved the `chat_gpt_call` method so that it won't fail if there is a large amount of text in the response.
- Removed the duplicate robots output from various places in `run_tool_for_gui.py`.

### Tuesday 4th March

04/03/25 03:15pm

- Added HTTP security header scanning.
- Removed `current_config` table from the database and reworked the startup database logic.
    - `config` is no longer wiped from start.
    - `load_config_into_db` got reworked.

### Monday 10th March

10/03/25 02:20pm

- `Previous scans` section added to left nav bar.
- Fixed a bug to do with `ffuf`
- Added the `concurrency_test` for the writeup.
- Updated default config.

### Thursday 13th March

13/03/25 03:50pm

- Renamed `__init__.py` to `flask_app.py`.
- Added a textarea in `advanced_settings` for the user to input their openai api key.
- Added robust changes to `chatgpt_call.py` so that the api key is retrieved from the config or env variable.
- Added a `verbose` and therefore a non `verbose` option to the user.
- Made the `ffuf` methods a bit more reliable.
- Improved the concurrency logic by changing the way that threads are distributed.
    - Instead of distributing the threads for each individual scan task, eg ffuf, dnsrecon, metasploit etc, they are now
      distributed for entire targets.
- Expand all option in multiple results.
- `ripley_cli.py` works now as if the user was using the gui. Just cant see results as nicely.

### Friday 14th March

14/03/25 06:10pm

- Added to the `select_commands_file` feature.
- Removed the SQLite db file from the repo.
- Removed `is_wordpress_site` from `utils.py` and instead let `run_wpscan` check this instead. Also found a bug and
  fixed the method so that it works properly.
- Added `default_extra_commands.txt`

### Saturday 15th March

15/03/25 02:05pm

- Removed `extra_commands_file` from the config and the database.
    - This entire feature now runs off `extra_commands` in the config.
    - Fixed all logic relating to this.
- Changed all instances of `session['config']` in `flask_app.py` from a list of 1 dict element to a dict.

### Tuesday 18th March

18/03/25 03:05pm

- Changed the `session['scan_results_file']` and `session['scan_result_file']` to instead store the filepath of a txt
  file that holds the locations of all temp JSON files with the results.
- Fixed the `scan_counter` logic.
- Fixed `get_screenshot()` not working when run as root.

### Wednesday 19th March

19/03/25 06:35pm

- Added `chatgpt_model` option to the config.
- Removed `output` folder and so all screenshots are saved in `flaskr/static/screenshots`.

### Friday 21st March

21/03/25 10:00am

- Added basic `port_info` to the results.
- Added `ffuf_redirect` to the config and made the ffuf methods in `scanner_tools.py` more readable.
- Made parts of `flask_app.py` more readable.
- Changed `ThreadPoolExecutor` to use the default `max_workers` which is "min(32, os.cpu_count() + 4)".

### Saturday 22nd March

22/03/25 11:35am

- Removed unwanted chars from the ChatGPT response for better readability.
- Added `speed` to the config so user can choose to have normal or slow scan speeds.
- Improved `check_and_kill_msf_rpc()` in `run_tool_for_gui.py` so that it finds the `msfrpcd` process with greater
  accuracy.

### Saturday 22nd March

22/03/25 04:05pm

- Small fix in metasploit section.
- Removed `host timeout` in port scanning settings.
- Added to `concurrency_test.py`

### Monday 24th March

24/03/25 03:20pm

- Changed colour scheme and improved various things in the GUI.
- Added `user_manual`
- Added the ffuf wordlists just in case.

### Tuesday 25th March

25/03/25 10:15am

- Reworked the wordlist check method.
- Added user manual button in homepage.