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
