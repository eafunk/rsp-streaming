Updated Nov. 30, 2019

The Resilient Streaming Protocol is an Internet protocol built on top of 
the Unreliable Datagram protocol (UDP) layer for transporting a unidirectional, 
high reliability, multimedia data stream and a low bit rate meta data stream 
where latency is not a concern.  The protocol is designed for one-way 
transmission, making it well suited for multicast distribution, but it 
also includes receiver reporting and requesting mechanism to allow for 
connection setup and teardown in a unicast distribution environment, 
and for listenership tracking in both multicast and unicast networks.

I designed and wote this protocol for use at my radio station, 
Mountain Chill Radio/KRKQ, for feeding our FM stransmitter and public 
Internet listening streaming server cluster from our studio. Our studio
and transmitter are located in the rugged San Jaun mountains of Colorado.
The difficult terrain and winter weather, along with low population density
makes it difficult and expensive to obtain unreliable network connectivity.
I designed this protocol to allow sereral low-cost, low reliablity network 
connection to work together to produce a reliable and stable streaming media 
link for the radio station.

In this project directory you will find:
- A detailed protocol documentation in the rsp_protocol.txt file. 

- Directions for generating a public/private key pair for optional
  use by the RSP protocol to prevent stream source spoofing in the
  rspKeyGen.txt file.

- C code for protocol implementation in the rsp-library directory.
  Both send and receive functions are implemented using either a 
  application call paced push or blocking pull approach, depending on 
  the end applications data rate timing design.

- An rsp protocol streaming relay server that makes use of rsp 
  library code in the rspServer directory. The rspServer directory 
  has a Makefile for building.  See the README.txt file within the 
  directory for details.

- A redimentry rsp stream player application (command line interface)
  that makes use of gstreamer1.0 playback pipleine is in the 
  gst-template/gst-app directory. 
  
  The gst-template build instructions, 
  using auto-make, for both gstreamer plugins and the playback application 
  are found within the gst-template directory.
  
- Gstreamer plugins that makes use of rsp library code to implement a 
  gstreamer1.0 rsp stream decoder and encoder (gstreamer source and sink 
  plugins) in the gst-template/gst-plugins directory. 
  
  Note that the rsp protocol is data content type agnostic, so other 
  gstreamer plugings are required to decode the rsp deliverd content 
  in a gstreamer pipeline, i.e. mp3, aac, etc.  The rsp protocol does 
  annouce the content type of the data being transported, assuming the 
  content type was properly specified on the encoder side of the stream. 
  The gst-template build instructions, using auto-make, for both 
  gstreamer plugins and the playback application are found within the 
  gst-template directory.
  
  **** ONLY A source (decoder) plugin is currently coded. A sink (encoder)
  pluging will be coded shortly, since I need it for another project. ****
