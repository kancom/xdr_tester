# xdr_tester

## Brief

An app which fills quasi-xdr from provided packets in pcap format.

## What's all about?

Imagine you have some network traffic processing tool, which generates some data based on the traffic and you want to check its results, then you can (at least I can) test the results with this app.
In my case we've got to check xDRs.

What's **XDR**? any-Data-Record. Here is explation of its ancestor [CDR](https://en.wikipedia.org/wiki/Call_detail_record) and my vision [how do they differ](https://stackoverflow.com/a/51760145/3621883)

You can define you XDR in csv format having formal specificatin how to fill each XDR's field. This definition is in CSV format.
Then you prepares pcap files which norrows down your case and fed it to the app.


## Usage

### CLI options

```
usage: dict_tester.py [-h] [-v] [--pcap PCAPFILE] [--xdr XDRFILE] [-d CSVDEL]
                      [-q CSVQUOT] [-s STARTFRAME] [-l PCAPLIMIT]

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Print version and exit
  --pcap PCAPFILE       path to pcap file
  --xdr XDRFILE         path to xdr file
  -d CSVDEL, --delimiter CSVDEL
                        csv field delimiter
  -q CSVQUOT, --quotechar CSVQUOT
                        csv field delimiter
  -s STARTFRAME, --startframe STARTFRAME
                        Start analysis from frame nb (1-based)
  -l PCAPLIMIT, --pcaplimit PCAPLIMIT
                        number of pkts to read
```


### Example usage

`python ./dict_tester.py --xdr ./isup.csv --pcap ./bicc.pcap`


### Example output

```
Start date = '1328723243.196280000'
End date = '1328723264.860039000'
IP Src = '10.121.15.152'
IP Dst = '10.191.16.205'
Port src = '3565'
Port dst = '3565'
LinkID = 'None'
ProbeID = 'None'
LocationID = 'None'
Record status = 'None'
Backward units = '10'
Towards units = '8'
Backward units size = '2912'
Towards units size = '1344'
Message type = '1'
Protocol type = '3'
NE src = 'None'
NE dst = 'None'
OPC = '4043'
DPC = '4043'
MTP3 NI = '2'
CIC = '23367'
Calling number = '116174354x'
Calling number NOA = '3'
Called number = '021998420793x'
Called number NOA = '3'
REL Cause value = 'None'
REL Cause location = 'None'
ACM Cause value = 'None'
ACM Cause location = 'None'
Location number = 'None'
Redirecting number = 'None'
Redirecting number NOA = 'None'
Original Called number = 'None'
Original Called number NOA = 'None'
Connected number = 'None'
Connected number NOA = 'None'
Charge indicator = 'None'
Releasing OPC = '4043'
Redirection indicator = 'None'
Redirection reason = 'None'
Dialing time = '0'
Setup time = 'None'
Ring time = '0'
Delay time = '0'
Conversation time = '0'
Release time = '0.407028000'
Holding time = '21.663759000'
Outgoing Echo = 'None'
Incoming Echo = 'None'
Media Src address = '10.107.24.68'
Media Src address IPv6 = 'None'
Media Src port = '35222'
Media Dst address = '10.198.26.75'
Media Dst address IPv6 = 'None'
Media dst port = '40690'
Media Src type = 'audio'
Media Dst type = 'audio'
Media Src proto = 'RTP/AVP'
Media Dst proto = 'RTP/AVP'
Orig Cause Value = 'None'
Cause location = 'None'
Answered = 'None'
Cause family = 'None'
Way = 'None'
xpi inst id = 'None'
XDR Messages = 'None'
1328723243.196280000 4043->4043 1
1328723243.196284000 4043->4043 1
1328723253.353792000 6572->6572 65
1328723253.366045000 6572->6572 65
1328723253.539737000 4043->4043 65
1328723253.539738000 4043->4043 65
1328723253.891999000 6572->6572 65
1328723253.905833000 6572->6572 65
1328723254.489863000 4043->4043 5
1328723254.489867000 4043->4043 5
1328723261.692483000 6572->6572 6
1328723261.706881000 6688->6688 6
1328723262.287607000 6572->6572 44
1328723262.301313000 6572->6572 44
1328723264.453011000 4043->4043 12
1328723264.453013000 4043->4043 12
1328723264.845839000 6572->6572 16
1328723264.860039000 6572->6572 16

```
