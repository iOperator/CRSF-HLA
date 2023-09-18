# CRSF-HLA
Saleae Logic 2 High Level Analyzer: Crossfire decoder for R/C protocol as used by TBS Crossfire, Tracer or ExpressLRS

## Getting started 🛠️

1. Install the CRSF analyzer in Logic 2 from the extensions menu. 😉
2. Create a new 'Async Serial' analyzer, set the baud rate to 420000, 8N1, LSB, non-inverted.
3. Create a new 'CRSF' analyzer, configure it and pick the previously created 'Async Serial' analyzer.
4. Done. 🚀

![Decode link statistics frame](images/decode_link_statistics.png)
![Decode RC channels packed frame](images/decode_rc_channels_packed.png)

## Features ✨

This is still a very early release. Currently the following frames are supported:

* Link statistics (0x14)
* RC channels packed (0x16)
* CRC check
* Destination device address

The decoder features a state machine that parses all frames so it can easily be extended to decode future frames.  
Some groundwork for additional frames already exists.

## ToDo ☝️

* Additional supported frames
* add check for aync serial
* pass parameters like address , len and all for all frames
* implement search for packet feature 
* add drop down for units in selection (ms or raw digital value)