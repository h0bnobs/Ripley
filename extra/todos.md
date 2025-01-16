# Todo

## Big picture things:
- HTTP response editor for webapps
- Basic reporting function for each target. PDF format. Colour and severity coded?
- Built in exploit module for metasploit
- Custom scripts/plugins
- Add verbose levels to cli version?
- Get all the tools needed beforehand?
- Asynchronous scanning mainly for things like nikto and webpage enumeration because they can take a long time.
- Parse the output of the ffuf scans and display it in a more readable format. Maybe parse them to txt files for easy reading and access.
- Let user choose their wordlist for ffuf. Right now it's hardcoded in ripley_cli.py.
- Let user opt out of ffuf.
- Correctly get a target from the multiple targets when displaying the command in extra commands.
- A way for the user to save extra commands they wanna run and use the same ones instead of typing them out each time.
- Let users select which HTTP response codes to ignore in the output of ffuf.
- Host discovery on a range of IPs. Either '->' or '-' or '/ notation'. Ping sweep?
- Add a way to save the output of the scans to a file. Button on results page?
- Add an opt-out for the chatgpt call in the config
- Add advanced config option to, if the chatgpt call is on, select which extra commands will be added to the chatgpt call.
- If the "token" aka the string for the chatgpt call is over x chars, trim the end off so that it still runs.
- If changes have been made locally in the frontend to the config, inform the user that the config has been changed and ask if they want to save it. (Text next to Update Config button!)
- Ffuf is only looking for https pages and subdomains.
- Ffuf is using the hardcoded wordlists. They need adding to the config.
- Update helper methods like is_target_webpage (in ripley_cli) and is_wordpress_site (in utils) so that they are more robust

## Lower level stuff:
- OS detection
- For the robots file, sort it into allow and disallow and get AI to point out the most interesting parts. 
- Remove 'multiple_targets' from config.
- Searching previous scans
- Learn the concurrency modules `concurrent.features` and `ThreadPoolExecuter()` for the writeup

## GUI specific todos:
- The option to save configs and reuse them
- Better way to select/input options to edit the config file
- Upgrade UI experience. Have selectors for single targets or like nessus, simply type in target(s) or give it a targets file instead of specifying.
