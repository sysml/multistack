# MultiStack - a framework to multiplex user-space and in-kernel stack

MultiStack is operating system support for user-level network stacks. MultiStack’s implementation revolves around four design principles. First, MultiStack supports a large number of dedicated stacks, to allow for having per-application stacks. Second, each stack has isolated access to the NIC, preventing stacks, some of which may contain untested or beta code, from interfering with each other. Third, MultiStack supports namespace isolation, whereby stacks register 3-tuples which are then used to multiplex incoming packets and to validate outgoing traffic for each application/stack instance. Finally, the system is able to accommodate legacy (in-kernel) stacks and application, providing an incremental deployment path

## Author

Michio Honda

## References

Michio Honda, Felipe Huici, Costin Raiciu, Joao Araujo and Luigi Rizzo, ["Rekindling network protocol innovation with user-level stacks"](http://www.sigcomm.org/sites/default/files/ccr/papers/2014/April/0000000-0000006.pdf), ACM SIGCOMM Computer Communication Review 44(2), 52-58, April, 2014

## Credits

MultiStack was developed in Laboratories Europe, partially supported by EU FP7 projects CHANGE, Trilogy2 and SSICLOPS, and NetApp