# infrastructure-kif
KIF - Kill It (with) Fire. Janitorial service for ASF Infra.
See https://github.com/humbedooh/kif for some more details.
This is a modified version that differs from upstream for now.


To install on an infra node, add the following yaml snippet to it:

~~~yaml
pipservice:
  kif:
    tag: master
~~~

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
