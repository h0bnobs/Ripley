# Todo

## Big picture things:
- HTTP response editor for webapps
- Automatic fuzzing
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
## Lower level stuff:
- OS detection
- For the robots file, sort it into allow and disallow and get AI to point out the most interesting parts. 
- Remove 'multiple_targets' from config.
- Make the 'view' button work in the previous_scans page.
- Maybe add a different page for multiple scan previous results. Maybe add a new table in the db for them as well because currently, the table is designed to work for single scans only.
- Acquiring the screenshot in the cli version is unoptimised because it currently performs two nmap scans (once at the beginning of ripley, and once again to check if the target is a webpage or not). This needs to be changed so that only 1 nmap scan is performed.
- Searching previous scans
- Learn the concurrency modules `concurrent.features` and `ThreadPoolExecuter()` for the writeup

## GUI specific todos:
- Drag and drop config files
- The option to save configs and reuse them
- Better way to select/input options to edit the config file
- Make it look nice.