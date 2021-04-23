# cielcg `[sjɛl si:dʒi:]`

alternative cgroup-tools (cgexec) implementation for both cgroup v1 and v2 (cgroup2)

following subcommands are implemented (some options might not be implemented though):

- cgclassify
- cgcreate
- cgdelete
- cgexec
- cgget
- cgset
- lscgroup
- lssubsys

these commands work for **cgroup v2** as well.

for your sake, `python -m cielcg [subcommand]` is also supported as well as launching as standalone script.

## variable conversions

some cgroup1/2 variable conversions refer to:

- https://blogs.oracle.com/linux/cgroup-v2-checkpoint
- https://lore.kernel.org/lkml/20160812221742.GA24736@cmpxchg.org/T/

