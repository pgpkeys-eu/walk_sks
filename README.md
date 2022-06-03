# walk_sks

A tool to draw pretty graphs of the SKS keyserver network

## Dependencies

* ruby
* graphviz

You must also have the following Ruby packages installed:

* nokogiri
* json
* yaml
* open-uri
* logger

## Usage

Note that the output directory defaults to `/var/www/html/graphs`, and neato is expected to be found in `/usr/bin/neato`.
You should edit the `walk_sks.rb` file if necessary to change these locations.
The output directory should already exist; if not, create it.

To run, invoke `./walk_sks.rb` on the command line.
Something like the following will be written to the output directory:

```
drwxrwxr-x  2 andrewg andrewg    4096 Jun  3 15:12 20220603-151102
lrwxrwxrwx  1 andrewg andrewg      29 Jun  3 15:12 walk-sks.yaml -> 20220603-151102/walk-sks.yaml
lrwxrwxrwx  1 andrewg andrewg      38 Jun  3 15:12 walk-sks.green.dot.svg -> 20220603-151102/walk-sks.green.dot.svg
lrwxrwxrwx  1 andrewg andrewg      32 Jun  3 15:12 walk-sks.dot.svg -> 20220603-151102/walk-sks.dot.svg
-rw-rw-r--  1 andrewg andrewg   28705 Jun  3 15:12 state.cache
-rw-rw-r--  1 andrewg andrewg 1191511 Jun  3 15:12 running.log
```

* The files `walk-sks.dot.svg` and `walk-sks.green.dot.svg` are the full and concise graphs respectively.
	* The full graph shows all known keyservers, including unreachable ones merely mentioned in another keyserver's membership file.
	* The concise graph shows all keyservers that have been reachable at some time in the past, as determined by the state cache.
* The `walk-sks.yaml` file is a machine-readable version of the data structure used to create the graphs.
* The graphs and yaml data are written to a subdirectory named after the current timestamp, and soft links into the latest subdirectory are maintained in the parent.
* The running log is automatically rotated out weekly.

The state cache is used for several things:

* to initialise spidering using the servers discovered on previous runs
* to determine which servers are worth including on the concise graph
* to display the last seen timestamp of a temporarily-offline server
* to display meaningful stats and connectivity for offline or clustered server (see below)

### Clustered keyservers

Many SKS servers are operated as a cluster of nodes behind a load balancer.
In such setups, it is common for only one node of the cluster to be configured for external sync.
When we spider a cluster we will more likely than not be load-balanced onto one of the nodes that is not configured for external sync, and so the membership list gathered by the spider will be incorrect.
In such cases, the membership list will likely consist of only internal (i.e. unroutable) IP addresses.
After we filter out unroutable addresses, if the membership list is empty we fall back on the cached membership list (if any).
This ensures that we continue to display a meaningful connectivity graph for the clustered keyserver, so long as we have correctly spidered it in the past.

## Credits

This spider was adapted from the code that runs <a href="https://sks-status.gwolf.org">sks-status.gwolf.org</a>.

