# KIF - Kill It (with) Fire
## A simple find-and-fix program with a yaml configuration

Kif is a simple monitoring program that detects programs running amok
and tries to correct them. It can currently scan for:

- Memory usage (MB, GB or % of total mem available)
- No. of open file descriptors
- No. of TCP connections open
- No. of LAN TCP connections open
- Age of process
- State of process (running, waiting, zombie etc)

and act accordingly, either running a custom command (such as restarting
a service) or killing it with any preferred signal. It can also notify
you of issues found and actions taken, either via email or hipchat.

See [kif.yaml](kif.yaml) for example configuration and features.

### Requirements
- python 3.6 or higher
- python-yaml
- python-psutil
- asfpy

### Installation and use
- Download Kif
- Make a kif.yaml configuration (see the [example](kif.yaml))
- Install the dependencies with: `pip3 install -r requirements.txt` (or use pipenv)
- Run as root (required to both read usage and restart services).
- Enjoy!


### Installing via pipservice
To install on an infra node, add the following yaml snippet to it:

~~~yaml
pipservice:
  kif:
    tag: master
~~~



### Rule syntax:

```yaml
rules:
    apache:
        description:     'sample apache process rule'
        # We can specify the exact cmdline and args to scan for:
        procid: 
            - '/usr/sbin/apache2'
            - '-k'
            - 'start'
        # We'll use combine: true to combine the resource of multiple processes into one check.
        combine:            true
        triggers:
            # Demand no more than 500 LAN connections
            maxlocalconns:  500
            # No more than 25,000 open connections in total
            maxconns:       25000
            # Require < 1GB memory used (could also be 10%, 512mb etc)
            maxmemory:      1gb
            # And finally, no more than 65,000 open file descriptors
            maxfds:         65000
        # If triggered, run this:
        runlist:
            - 'service apache2 restart'
            
    zombies:
        description:    'Any process caught in zombie mode'
        # use empty procid to catch all
        procid:         ''
        triggers:
            # This can be any process state (zombie, sleeping, running, etc)
            state:      'zombie'
        # No runlist here, just kill it with signal 9
        kill:           true
        killwith:       9
        
    puppet:
        description:    'kill -9 puppet agents that are hanging'
        procid: 'puppet agent'
        # Find all processes created more than 1 day ago.
        triggers:
            maxage: 1d
        # Ignore main process
        ignorepidfile:  '/var/run/puppet/agent.pid'
        # Kill it with signal 9
        kill:           true
        killwith:       9
```

### Restricting rules to certain machines

To have a specific rule run on certain nodes, please add the rule to kif.yaml, and make use of `host_must_match` or `host_must_not_match` definitions to narrow down where to run the rule-set, like so:

~~~yaml
  zombies_on_gitbox:
    description:    'Any gitweb process caught in zombie mode'
    host_must_match: gitbox.apache.org
    procid:         '/usr/bin/git'
    triggers:
        # This can be any process state (zombie, sleeping, running, etc)
        # Or a git process > 30 minutes old.
        state:      'zombie'
        maxage:      30m
    kill:           true
    killwith: 9
  
  httpd_but_not_tlpserver:
    description:         'httpd too many backend connections (pool filling up?)'
    host_must_not_match: 'tlp-.+'
    procid:              '/usr/sbin/apache2'
    # Use combine: true to combine the resource of multiple processes into one check.
    combine:             true
    triggers:
        maxlocalconns:   1000
    runlist:
        - 'service apache2 restart'
~~~

Both `host_must_match` and `host_must_not_match` are regular expressions and must match the full hostname.
Be sure to use double escaping for keywords, for instance `\\d` instead of `\d`, or the yaml will break. The must/must-not can also be used in combination to include some nodes and rule out others.

### Command line arguments

- `--debug`: Run in debug mode - detect but don't try to fix issues.
- `--config $filename`: path to config file.
