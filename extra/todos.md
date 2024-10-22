# Todo

## Big picture things:
- GUI - Flask or customtkinter?
- HTTP response editor for webapps
- Automatic fuzzing
- Basic reporting function for each target. PDF format. Colour and severity coded?
- Built in exploit module for metasploit
- Custom scripts/plugins
- Add verbose levels to cli version?
- Get all the tools needed beforehand?
- Some kind of information storage about the target. Suggestions based upon this information.

## Lower level stuff:
- OS detection
- Detect whether it's a webapp test or infrastructure target
- Concurrency
- Change the testing methods so that they use [run_commands.py](../scripts/run_commands.py)
- Get the run_commands.py methods to return the results, so that custom error messages are returned e.g:
  - If smbclient returns the string "Command 'smbclient -L 129.12.232.4' returned non-zero exit status 1." then along with this, a nice custom error message is printed as well, eg "smbclient found no shares that could be listed!" (with the colours and symbols!)

## GUI todos:
- Add clear division for output of different targets
- Drag and drop config files
- The option to save configs and reuse them
- Better way to select/inpput options to edit the config file
- When the config file is updated in the gui, its updated in project root dir