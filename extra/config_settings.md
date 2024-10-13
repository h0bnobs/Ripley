### Blank:
<pre>
{
    "single_target": "",  
    "multiple_targets": "",
    "targets_file": "",
    "nmap_parameters": ""
}
</pre>

### Example for a single target:
<pre>
{
    "single_target": "www.kent.ac.uk",
    "multiple_targets": "",
    "targets_file": "",
    "nmap_parameters": "-Pn"
}
</pre>

### Examples for multiple targets:
<pre>
{
    "single_target": "",
    "multiple_targets": "",
    "targets_file": "targets.txt",
    "nmap_parameters": "-Pn"
}

Where the contents of targets.txt consists of 2 lines 
containing "www.kent.ac.uk" and "www.google.co.uk"
</pre>
<pre>
{
    "single_target": "",
    "multiple_targets": ["www.google.co.uk", "www.kent.ac.uk"],
    "targets_file": "",
    "nmap_parameters": "-Pn"
}
</pre>