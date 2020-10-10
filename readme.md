!!! We did not release DEC V6.0 beta 1 yet
!!! This file is only in preparation of such a release
!!! When we release, the release will appear on the
!!! release tab in GitHub!

!!! The project changed license!
!!! We moved from MPL 1.0 to Apache 2.0 license

# DEC - Delphi Encryption Compendium

## What is DEC?
DEC is a library for Embarcadero Delphi, containing different cryptographic algorithms .
It contains algorithms for these categories:

* Ciphers: encryption/decryption of data
* Hashes: "cryptographic checksums"
* A cryptographic pseudo random number generator
* CRCs: non cryptographic checksums based on CRC algorithms

## Which Delphi versions does it support?
The last released version 5.2 is compatible with Delphi 7-2007 at least.
For using it with newer versions some small modification is necessary in order 
to compile it. If done it is compatible up to 10.2 Tokio at least.
This version is only compatible with Win32/Win64!

Version 6.0 is still in development and supports Delphi 2009 - Delphi 10.4 Sydney. 
When defining the NO_ASM define in DECOptions.inc it is compatible with all platforms!

## What is the current status?
If you look at the release tab you see a 5.2 release from 2015 so
the project looks a bit dead. Looking closer at the insights
or at the source code in development and master branch, however, you will notice 
that there has been a lot activity since then aimed at releasing a V6.0. 
Details about the changes and additions in V6.0 can be found in the DEC60.pdf 
file in the docs subfolder of the development branch.

In comparison to 5.2 we added some console, VCL and FMX based demo applications.
The FMX based demos are even available via Google play as "DEC cipher demo" and
"DEC hash demo".

## Why is V6.0 not released yet?
We are still working on some bugfixes and finalizing the documentation.
As soon as these things are done we will release this new version. Please
keep in mind that we are working on this in our limited spare time!

## Where can I get further information? For example if I'd like to contribute?
In the root folder of DEC V6.0 you will find further files with information about 
this project like *NOTICE.txt*, *CONTRIBUTING.md*, *SECURITY.md*.
Also take the time to read DEC60.pdf in the *Docs* folder or look at the demos 
provided in the *Demos* subfolder.

## Has it been tested?
DEC 5.2 comes with some "arcane" test program testing the algoithms implemented
using test data supplied via some text file. For many algorithms this test data
stems from official documentation of the algorithms itsself. DEC 5.2 passes these 
tests.

DEC 6.0 reworked these tests into DUnit and DUnitX tests. We also added some more 
tests and with this replaced the "arcane" test program which used hard to understand 
code. A few of the implemented unit tests still fail, but this is simply because
they are empty scheletons at this point in time waiting to be filled in. We first 
need to work out how to implement these tests and maybe look for test data.
Why don't you help out by researching useful test data for those few tests?
