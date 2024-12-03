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