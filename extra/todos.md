# Todo

## Big picture things:
- GUI - Flask or customtkinter?
- HTTP response editor for webapps
- Automatic fuzzing
- Basic reporting function for each target. PDF format. Colour and severity coded?
- Built in exploit module for metasploit
- Custom scripts/plugins

## Lower level stuff:
- OS detection
- Detect whether it's a webapp test or infrastructure target
- Concurrency
- Change the methods so that they use run_commands.py

## Config file todos:
- Add logic that detects if what has been declared in the config is a filename of a list of targets, instead of just a list of targets. If it is, read the file and extract the targets from it.