# Todo

## Big picture things:
- HTTP response editor for webapps
- Basic reporting function for each target. PDF format. Colour and severity coded?
- Built in exploit module for metasploit
- Custom scripts/plugins
- Add verbose levels to cli version?
- Get all the tools needed beforehand?
- Asynchronous scanning mainly for things like nikto and webpage enumeration because they can take a long time.
- Let the user add their own tools/commands to the entire scan, eg let them run a tool that isn't yet in ripley, or let them run their own scripts.
- Parse the output of the ffuf scans and display it in a more readable format. Maybe parse them to txt files for easy reading and access.
- Start ffuf concurrently at the same time as the rest of the scan.
- Extra commands. The config is broken and the feature does nothing for now.
- Sort previous scans by date.
- Let user choose their wordlist for ffuf. Right now it's hardcoded in ripley_cli.py.
- Let user opt out of ffuf.

## Lower level stuff:
- OS detection
- For the robots file, sort it into allow and disallow and get AI to point out the most interesting parts. 
- Remove 'multiple_targets' from config.
- Searching previous scans
- Learn the concurrency modules `concurrent.features` and `ThreadPoolExecuter()` for the writeup

## GUI specific todos:
- Drag and drop config files
- The option to save configs and reuse them
- Better way to select/input options to edit the config file
- Make it look nice.