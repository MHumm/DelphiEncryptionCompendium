DEC V6.0 beta 1 readme

Please read these information thoroughly before using this library 
for production code.

Also read the documentation contained in the docs subfolder.

This is the first prerelease version for the upcomming version 6 of DEC,
the Delphi Encryption Compendium.

The aim of V6.0 is not to add new crypto algorithms but to restructure DEC
in such a way that new algorithms can be easily integrated and to make it
cross platform compatible. This shall provide a solid base for the future
implementations of newer hash-, cipher- and padding algorithms. Another aim
is better documentation than before and inclusion of some demo apps.

Current status of beta 1:

- the interface should be nearly complete
- most of it can be compiled for other platforms than Win32/Win64
- Some of the unit tests still fail so those algorithms most likely still 
  have bugs. The algorithms concerned are:

  - 

- the Whirlpool hash algorithm is said to not match the oficially 
  standardisized one
- the SHA hash algorithm most likely will be renamed in SHA0 for cleaness 
  reasons

- in DECOptions.inc you can enable an x86 ASM mode. This is usefull for the
  Win32 platform only and enabling it currently crashes the compiled app at 
  startup due to some still unresolved failure in our initialization code 
- some of the demos do not work yet
- the documentation is not complete yet
- XML doc in our code might not be 100% complete yet or as meaningful as we 
  like it to be