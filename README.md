# PRC Flowmeter v0.0.1
Flowmeter is a Scapy-based tool for deriving statistical features from PCAPs for data analysis and machine learning. The features are based on the java application [CICFlowmeter](https://github.com/ahlashkari/CICFlowMeter/)

Based heavily on [this flowmeter app](https://github.com/alekzandr/flowmeter)

# Usage
A Flowmeter object is created with up to three parameters:

* offline (str) - filename of a pcap file; if none provided, streams from available ports (requires run as admin in linux-based environments.)
* outfunc (function) - a csv rendition of the metered flows will be sent to this function as they are created. If none provided, will default to print().
* outfile (str) - filename to store csv flow output. If none is provided, results are not stored.

Building off of scapy Sessions, Flowmeter separates packet streams into distinct network communication 'flows', which are identified simply as communications between two endpoints (ip:port) on a given protocol within a period of time. From there it begins analyzing the flow data to derive features useful for plotting, traffic pattern analysis, and machine learning.

```
from flowmeter import Flowmeter

feature_gen = Flowmeter(
    offline = "1548216696.814641.pcap",
    outfunc = None,
    outfile = "1548216696.814641")

feature_gen.run()

```

### Current goals include:
* Adding the ability to stream packets from a live socket
* Adding the ability to stream directly to a csv file

# Contributions
If you would like to contribute feel free to fork the repo, clone the project, submit pull requests, open issues, or request features/enhancements.

# License
PRCFlowmeter is currently licensed under the GNU GPLv2.
