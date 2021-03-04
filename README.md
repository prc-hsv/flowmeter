# PRC Flowmeter v0.0.1
Flowmeter is a Scapy-based tool for deriving statistical features from PCAPs for data analysis and machine learning. The features are based on the java application [CICFlowmeter](https://github.com/ahlashkari/CICFlowMeter/)

Based heavily on [this flowmeter app](https://github.com/alekzandr/flowmeter)

# Usage
A Flowmeter object is created by taking in a PCAP file as a parameter. Using the build_feature method, Flowmeter separates out the PCAP into distinct TCP and UDP flows. From there it begins analyzing the flow data to derive features useful for plotting, traffic pattern analysis, and machine learning.

```
from flowmeter.flowmeter import Flowmeter
import pandas as pd

feature_gen = Flowmeter("1548216696.814641.pcap")
df = feature_gen.build_feature_dataframe()

df.to_csv("1548216696.814641.csv")
```

### Note:
The current implementaion is still in its early versions and inefficient at handling memory. We are currently beginning optimizations to reduce memory usage and provide a more stable process. Processing a large PCAP can be very MEMORY INTENSIVE. Additionally, Flowmeter does not work in jupyter notebooks due to how notebooks handle multiprocesses pooling.

### Current goals include:
* Adding the ability to stream packets from a live socket
* Adding the ability to stream directly to a csv file

# Contributions
If you would like to contribute feel free to fork the repo, clone the project, submit pull requests, open issues, or request features/enhancements.

# License
Flowmeter is currently licensed under the GNU GPLv2.
