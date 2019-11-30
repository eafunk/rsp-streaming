Updated Nov. 30, 2019

RspServer is a multi-stream relay server which accepts rsp source streams
providing relay of the stream to multiple rsp stream listeners requests, 
and optionaly, relaying of the rsp source streams to shoutcast listeners.
In addition, rspServer can be configured to send static rsp streams to 
pre-defined address and port combinations.  This is usefull to cross-feed 
multiple rspServers for redundancy, or to provide static redundant streams
to an rsp listerner who moun other wise only recieve a stream by request 
to an rspServer.  Clustering of cross-fed arServers is supported.  As is 
transcoding of the stream data content format through an external program, 
and reformating of the rsp packet format when the source stream has different
rsp interleaver layout than is desired for the listener stream.

Source streams are expected to be static streams, send to the server
address on a configureded UDP port.

*** REQUIRED BUILD LIBRARIES AND C HEADER FILES ***

libcrypto

*** BUILDING ***

Makefile is very basic at this point. Run the CLI "sudo make" command
from this directory, and then if there are no errors, run 
"sudo make install" to place the compiled rspServer in /usr/local/bin/
directory.

*** RUNNING ***

Run rspServer with no command arguments for the the help list. i.e.:

/usr/local/bin/rspServer

Run rspServer with the -c option to start a server instance using the given
configuration file settings. i.e.:

/usr/local/bin/rspServer -c path/to/config/file

Run rspServer with the -s option and a command to interact with a running rspServer
instance. Again, run with no arguments for a help list showing the possible commands.
For example to get the status of a running rspServer, running with a control socket 
at /tmp/rspServerSock, as specified in the instance configuration file it was run:

/usr/local/bin/rspServer -s /tmp/rspServerSock status

See the included configuration file example in the example_confg directory. This
directory also included some listen request jSON files for used by the rsp library
and/or the gstreamer source pluging to request streaming from a rspServer.
