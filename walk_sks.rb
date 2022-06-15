#!/usr/bin/env ruby
# coding: utf-8

#######################################################################
# walk_sks.rb
#
# A script to walk the SKS peering mesh and print pretty graphs
#
# © Gunnar Wolf 2019-2021, Andrew Gallagher 2021-2022
#######################################################################

require 'open-uri'
require 'nokogiri'
require 'logger'
require 'yaml'
require 'json'

GraphvizBin = '/usr/bin/neato'
SksStatusDir = '/var/www/html/graphs/'

Log = Logger.new(File.join(SksStatusDir, 'running.log'), 'weekly', 4)
Log.level = Logger::INFO

Ourselves = "spider.pgpkeys.eu"

StatsMinHistory = 100 # minimum history entries required for meaningful stats
HistoryMaxEntries = 1500 # this allows us to measure three nines
RecentlySeenDays = 30 # how long to keep a dead node around before clearing its history

# Always include the following servers in the startfrom list
StartFrom = [
  'pgpkeys.eu 11370',
#  'hkp.openpgpkeys.net 11370', # temporarily down as of 20211217
  'keyserver.ubuntu.com 11370'
]
StatsPage = 'pks/lookup?op=stats&options=mr'
Servers = {}
Status = {}
# We do not verify mailsync peers (email addresses).
# Also skip unroutable IP addresses, non-fqdn hosts, etc.
# NB: regexes apply to the space-separated-values Server type, not hostnames.
ServerExclude =  [
  /@/,
  /^localhost/,
  /^127\./,
  /^::1/,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6789]|2[0-9]|3[01])\./,
  /^2(2[4-9]|3[0-9])\./,
  /^169\.254\./,
  /^fc7[cd]:/,
  /^fe80:/,
  /^ff[0-9a-f][0-9a-f]:/,
  /^[a-zA-Z0-9_-]+\s/
]
# Some servers have obfuscated peering connections via unroutable bare ips.
# Some DNS hosts have CNAMEs. We maintain them by hand for now.
# Note that HTTP redirects/proxies DO NOT affect the recon protocol.
HostAliases = {
  "pgpkeys.eu" => ["fr.pgpkeys.eu"],
  "sks.pgpkeys.eu" => ["de.pgpkeys.eu"],
  "hkp.openpgpkeys.net" => ["pgp.gwolf.org"],
  "keyserver1.computer42.org" => ["keyserver.computer42.org"],
  "gozer.rediris.es" => ["pgp.rediris.es"], # pgp is a round-robin for zuul and gozer, but zuul is currently broken
  "pgp.surf.nl" => ["pgp.surfnet.nl"],
  "sks.pyro.eu.org" => ["keyserver.sincer.us"],
  "openpgp.circl.lu" => ["pgp.circl.lu"],
  "keywin.trifence.ch" => ["keyserver.trifence.ch"],
  "keyserver.spline.inf.fu-berlin.de" => ["vm-keyserver.spline.inf.fu-berlin.de"],
  "pgp.mit.edu" => ["cryptonomicon.mit.edu"],
  "raxus.rnp.br" => ["keyserver.cais.rnp.br"],
  "sks.srv.dumain.com" => ["key-server.org"],
  "keyserver.ubuntu.com" => ["10.15.42.5", "10.15.42.9"], # hockeypuck-0, hockeypuck-1
  "keyserver1.canonical.com" => ["10.15.42.21"]           # hockeypuck-external-0
}

now = Time.now.utc
ISOTimestamp = now.iso8601
RecentlySeenLimit = (now - RecentlySeenDays*86400).iso8601
Log.info("Time now %s; Recently seen since %s; History length %s" % [ ISOTimestamp, RecentlySeenLimit, HistoryMaxEntries ])

# don't use iso8601 in filenames, the colons will break scp
OutDirTimestamp = '%04d%02d%02d-%02d%02d%02d' % [now.year, now.month, now.day, now.hour, now.min, now.sec]
OutDir = File.join(SksStatusDir, OutDirTimestamp)
Dir.mkdir(OutDir)
Dot={
  'filehandle' => File.open(File.join(OutDir, 'walk-sks.dot'), 'w+'),
  'mutex' => Mutex.new
}
GreenDot = File.open(File.join(OutDir, 'walk-sks.green.dot'), 'w')

# Initialise our running cache from the saved copy on disk
StateCache = File.join(SksStatusDir, 'state.cache')
if File.exist?(StateCache)
  PersistentState = JSON.parse(File.read(StateCache))
else
  PersistentState = {}
end

PersistentState['servers'] ||= {}

if PersistentState['INIT']
  # Merge the hardcoded and cached lists of initial servers.
  # No need to deduplicate here, as walk_from() does it below.
  StartFrom.concat(PersistentState['INIT'])
end
# We recalculate INIT every time from the discovered state
PersistentState['INIT'] = []

## Unsolved problem - how to cache-expire persisted discovered aliases?
#if PersistentState['aliases']
#  # Merge the hardcoded and cached lists of host aliases.
#  HostAliases.concat(PersistentState['aliases'])
#end

# Generate the inverse of the host aliases map for convenience
HostCanonicals = {}
HostAliases.each do | primary, alts |
  alts.each do | alt |
    HostCanonicals[alt] = primary
  end
end
AliasesMutex = Mutex.new

MeanKeys = { 'mean' => 0, 'count' => 0, 'mutex' => Mutex.new }
if PersistentState['meankeys']
  # In the unlikely event that the first server polled has missing keys, we can
  # use the cached value of meankeys as an initial data point to detect it.
  MeanKeys['mean'] = PersistentState['meankeys']
  MeanKeys['count'] = 1
  Log.info("MeanKeys rollover %d from %d" % [ MeanKeys['mean'], MeanKeys['count'] ])
end


#################
#################


def update_aliases(source, target)
  if source =~ /^(\S+) /
    sourceHost = $1
  else
    return nil
  end
  if target =~ /^(\S+) /
    targetHost = $1
  else
    return nil
  end
  # Needs a mutex, as is called by concurrent threads in walk_from()
  AliasesMutex.lock
  HostCanonicals[sourceHost] = targetHost
  if HostAliases.has_key?(targetHost)
    HostAliases[targetHost].append(sourceHost)
  else
    HostAliases[targetHost] = [sourceHost]
  end
  AliasesMutex.unlock
end

def update_mean(what)
  # Needs a mutex, as is called by concurrent threads in walk_from()
  MeanKeys['mutex'].lock
  MeanKeys['mean'] = (what + MeanKeys['mean']*MeanKeys['count'])/(MeanKeys['count'] + 1)
  MeanKeys['count'] = MeanKeys['count'] + 1
  Log.info("MeanKeys is now %d from %d" % [ MeanKeys['mean'], MeanKeys['count'] ])
  MeanKeys['mutex'].unlock
end

def graph(what)
  # Needs a mutex, as is called by concurrent threads in walk_from()
  Dot['mutex'].lock
  Dot['filehandle'].puts what
  Dot['mutex'].unlock
end

def green_graph(what)
  # This is generated by the already-static Dot graph, so no mutex is needed
  GreenDot.puts what
end

def preen_connections()
  # Filter all peer lists one last time to catch any racy updates
  Servers.keys.each do |server|
    peers = filter_peers(Servers[server])
    PersistentState['servers'][server]['peers'] = peers
    Servers[server] = peers

  end
end

def graph_connections()
  # Deduplicate mutual connections by keeping a hash of arrays
  mutualsDrawn = {}
  # only graph the servers discovered in this run, not the full cache
  Servers.keys.each do |server|
    mutualsDrawn[server] = []
    (Servers[server] || []).each do |peer|
      # Skip if we already drew our own inverse, or if the link is reflexive
      if ! (mutualsDrawn[peer] && mutualsDrawn[peer].include?(server)) && server != peer
        if Servers[peer] && Servers[peer].include?(server)
          # Draw a mutual as a heavy, directionless line.
          attributes = "color=black, dir=both, arrowsize=0.5, penwidth=2, weight=3"
          # Remind ourselves to skip the second, inverse link
          mutualsDrawn[server].append(peer)
        else
          # Draw a non-mutual as a light, directioned line
          attributes = "color=grey60, arrowsize=0.5, arrowtail=dot, dir=both"
        end
        graph ' "%s" -> "%s" [%s];' % [server, peer, attributes]
      end
    end
  end
end

def greenify(data)
  # The "green graph" is the graph of interesting nodes, however this is not
  # just green-coloured nodes, but any that were tagged "pass" during the walk.

  # The 'data' parameter is an array of lines from the full Dot graph
  nodes = {}
  res = []

  # First pass: We look for all of the green nodes, ignoring nodes of
  # any other color. We ignore all connections as well.
  data.each do |lin|
    next unless lin =~ /^\s+"([^"]+)".+\Wcomment="[^"]*\bpass\b[^"]*"/;
    nodes[$1] = 1
    res << lin
  end

  # Second pass: All of the connections between green nodes
  data.each do |lin|
    next unless lin =~ /^\s+"([^"]+)" -> "([^"]+)"/
    from = $1
    to = $2
    next unless nodes[from] and nodes[to]
    res << lin
  end

  return res
end

def filter_peers(peers)
  peers = peers.map do |peer|
    peer.downcase!
    # Canonicalize "host:reconPort" to "host reconPort"
    if peer =~ /^([[:alnum:].-]+)(\s+|:)(\d+)$/
      "%s %s" % [ ( HostCanonicals[$1] || $1 ), $3 ]
    elsif peer =~ /^(.*:.*:.*)(\s+|:)(\d+)$/
      # If it has two or more colons in it, then it's IPv6 :-)
      "[%s] %s" % [ ( HostCanonicals[$1] || $1 ), $3 ]
    end
  end
  # Do not consider peers on the ServerExclude list, and remove nils
  return peers.compact.reject do |peer|
    peer.match?(Regexp.union(ServerExclude))
  end
end

def nines(history)
  # Get the frequency of "." statuses in N-nines format (as an integer)
  return nil if history.length < StatsMinHistory
  # Divide by history.size+1 so that we can never report 0% errors
  errorRate = 1-history.count(".").fdiv(history.size+1)
  nineDigits = 0.5-Math.log10(errorRate)
  # But just in case...
  return nil if nineDigits.infinite?
  return nineDigits.to_i
end

def walk_from(server)
  raise RuntimeError, 'wrong data format' unless server.is_a? String

  if server =~ /^(.+) (\d+)$/
    host, reconPort = $1, $2
  else
    Log.warn('Could not parse server line: «%s». Ignoring.' % server)
    return nil
  end

  return nil if Servers.has_key?(server) # Already visited
  Servers[server] = [] # Populate immediately to block duplicate threads
  PersistentState['servers'][server] ||= {}
  peers = []

  Log.info("%3d visited; walking from %s" % [Servers.keys.size, server])

  # Hardcode canonical's nonstandard hkpPort
  if host =~ /\.canonical\.com$/
    hkpPort = 11001
  # Ignore persistent state as we don't yet dynamically detect
  #elsif PersistentState['servers'][server]['hkpPort']
  #  hkpPort = PersistentState['servers'][server]['hkpPort']
  else
    # Only a server's peers can query its recon service to obtain the hkpPort
    # so let's make a sweeping assumption.
    hkpPort = reconPort.to_i + 1
  end

  uri = 'http://%s:%s/%s' % [host, hkpPort, StatsPage]

  begin
    Log.info('Opening server at %s' % uri)
    stats = Nokogiri(URI.open(uri, options = {:redirect => false}))
    begin
      # Prefer JSON parsing
      struct = JSON.parse(stats.search('p').first)
      selfHostname = struct["hostname"]
      selfNodename = struct["nodename"]
      peers = struct["peers"].map { |peer| peer["reconAddr"] }
      numkeys = struct["numkeys"] || struct["Total"]
      software = struct["software"]
      fontcolor = "white"
      Log.info("Parsed JSON stats page for #{server}")
    rescue
      # fall back to HTML DOM parsing
      settingsRows = stats.xpath('//*[@summary="Keyserver Settings"]/tr')
      settingsMap = {}
      settingsRows.each do |tr|
        key = tr.xpath('td[1]').first.inner_text.gsub(/:$/, "")
        value = tr.xpath('td[2]').first.inner_text
        settingsMap[key] = value
      end
      selfHostname = settingsMap['Hostname']
      selfNodename = settingsMap['Nodename']
      peers = stats.xpath('//*[@summary="Gossip Peers"]').first.search('td').map {|td| td.inner_text}
      title = stats.search('title').first.inner_text
      if title =~ /^(\w+) /
        software = $1
      else
        software = "(unknown)"
      end
      numkeys = stats.search('p').map {|p| p.inner_text =~ /^Total number of keys: (\d+)$/ && $1}.compact.first
      fontcolor = "yellow"
      Log.info("Parsed HTML stats page for #{server}")
    end

    if selfHostname && selfHostname != host
      # We've found an alias. First check if we're already mapped together
      # Note that filter_peers operates on an array
      selfServer = "#{selfHostname} #{reconPort}"
      filterSelfServer = filter_peers([selfServer])[0]
      if filterSelfServer && filterSelfServer != server
        # This is a new, non-excluded alias, make a note of it for the future.
        if Servers.has_key?(filterSelfServer)
          # Another thread got here already; make like a hole in the water
          Log.info("Already seen '#{filterSelfServer}', skipping '#{server}'")
          Servers.delete(server)
          PersistentState['servers'].delete(server)
          # Add ourselves to the list of aliases of the "real" server
          Log.info("Adding alias '#{server}' for '#{filterSelfServer}'")
          update_aliases(server, filterSelfServer)
          return nil
        else
          # We are first, add selfServer as alias of us to block other threads
          Log.info("Adding alias '#{filterSelfServer}' for '#{server}'")
          update_aliases(filterSelfServer, server)
        end
      end
    end

  # These errors can be load-related or otherwise transitory.
  rescue Net::OpenTimeout, Errno::ENETUNREACH, Errno::EHOSTUNREACH, Errno::ECONNREFUSED => e
    color, fontcolor, status, statusByte = 'yellow', 'black', e.class, 'R'
  rescue OpenURI::HTTPError, OpenSSL::SSL::SSLError => e
    color, fontcolor, status, statusByte = 'orange', 'black', e.class, 'S'
  rescue Net::ReadTimeout => e
    color, fontcolor, status, statusByte = 'red', 'black', e.class, 'T'

  # These errors tend to be due to nonexistence or misconfiguration.
  rescue OpenURI::HTTPRedirect => e
    # We should probably catch this and follow, but that means detecting loops
    color, fontcolor, status, statusByte = 'grey90', 'red', e.class, 'N'
  rescue NoMethodError
    # Attempted to dereference nil (does not serve ?op=stats perhaps?)
    # ABG: NB this also catches my sloppy programming errors :-)
    color, fontcolor, status, statusByte = 'grey90', 'blue', 'Not a keyserver', 'N'
  rescue SocketError
    color, fontcolor, status, statusByte = 'grey90', 'black', 'No such server', 'N'
  rescue Exception => e
    color, fontcolor, status, statusByte = 'black', 'white', e.class, '?'

  else
    color, status, statusByte = 'green', 'ok', '.'
    PersistentState['servers'][server]['lastSeen'] = ISOTimestamp
    PersistentState['servers'][server]['hkpPort'] = hkpPort
    PersistentState['servers'][server]['software'] = software
  end

  Thread.current[:output] = statusByte

  if ! software
    if PersistentState['servers'][server]['software']
      # Assume the server is still running the same software as last time
      software = "(%s)" % [PersistentState['servers'][server]['software']]
    end
  end

  if numkeys
    # Update cached numkeys IFF we got a real numkeys from the server
    # NB: a working server can return no numkeys if it has just been restarted
    PersistentState['servers'][server]['numkeys'] = numkeys
    description = '%s (%dk)' % [software, numkeys.to_i/1000]
  elsif PersistentState['servers'][server]['numkeys']
    # use cached numkeys ONLY for display purposes, not for calculations
    cachedNumkeys = PersistentState['servers'][server]['numkeys']
    description = '%s (%dk?)' % [software, cachedNumkeys.to_i/1000]
  else
    description = software
  end

  recordHistory = false
  greenFilter = "fail"
  if status == "ok"
    recordHistory = true
    greenFilter = "pass"
  elsif PersistentState['servers'][server]['lastSeen']
    lastSeen = PersistentState['servers'][server]['lastSeen']
    description = "%s\\nLast seen: %s" % [description, lastSeen]
    # the server may come back shortly, so keep recording stats
    recordHistory = true
    greenFilter = "pass"
  end

  # Compare numkeys to a running floor, and warn if the current value is low
  if numkeys.to_i > MeanKeys['mean'] * 0.99
    if StartFrom.include? server
      # Only consider the starting servers when calculating the floor
      update_mean(numkeys.to_i)
    end
  elsif status == 'ok'
    status = 'slow'
    color = 'darkcyan'
    statusByte = '-'
  end

  # Keep note of the good servers for next time
  if status == 'ok'
    PersistentState['INIT'].append(server)
  end

  Status[Thread.current[:output]] ||= []
  Status[Thread.current[:output]] << server
  if HostCanonicals.has_key?(host)
    canonical = HostCanonicals[host]
    nameList = "%s\\n%s" % [canonical, HostAliases[canonical].join("\\n")]
  elsif HostAliases.has_key?(host)
    nameList = "%s\\n%s" % [host, HostAliases[host].join("\\n")]
  else
    nameList = host
  end

  # populate history and calculate reliability stats
  # the history can get very large, so let's keep it compact
  if recordHistory == true
    PersistentState['servers'][server]['history'] ||= ""
    if PersistentState['servers'][server]['history'].length >= HistoryMaxEntries
      PersistentState['servers'][server]['history'].slice!(0)
    end
    PersistentState['servers'][server]['history'] << statusByte
    reliability = nines(PersistentState['servers'][server]['history'])
    if reliability
      description << " %dN" % [ reliability ]
      Log.warn("History of %s demonstrates %s nines reliability" % [server, reliability])
    end
  else
    PersistentState['servers'][server]['history'] = ""
  end

  # Graph the node now, we'll graph the connections later
  graph ' "%s" [color=%s, fontcolor=%s, label="%s\\n%s", comment="%s %s"];' % [server, color, fontcolor, nameList, description, status, greenFilter]

  # Expire nodes and node history
  if lastSeen && lastSeen < RecentlySeenLimit
    Log.warn("#{server} was last seen at #{lastSeen}, before #{RecentlySeenLimit}; demoting")
    PersistentState['servers'][server].delete('lastSeen')
  end

  peers = filter_peers(peers)
  if peers.size == 0 && PersistentState['servers'][server]['peers'] && PersistentState['servers'][server]['peers'].length != 0
    Log.warn("#{server} returned no peers, falling back to cache")
    # run persisted peers through the filter, just to be sure
    peers = filter_peers(PersistentState['servers'][server]['peers'])
  end

  PersistentState['servers'][server]['status'] = status
  PersistentState['servers'][server]['peers'] = peers
  Servers[server] = peers

  fork(server, peers)
end

def fork(server, peers)
  threads = []
  thr_status = {}
  peers.each do |peer|
    threads << Thread.new {walk_from(peer)}
  end
  threads.each do |t|
    t.join
    out = t[:output]
    thr_status[out] ||= 0
    thr_status[out] += 1
  end
  my_threads = thr_status.map {|k,v| "#{k}: #{v}"}.join(' - ')
  Log.info("Thread for #{server} joined (#{thr_status.size}): #{my_threads}")
end

####################
##### Let's go #####
####################

# Common graph elements. NB the name of the graph is "" so that the background
# does not raise a tooltip in the viewer.
MinskyExplanation = '"Minsky set reconciliation requires mutual configuration; unilateral configuration will (in general) not work."'
Log.info('Starting SKS network probe and analysis')
['strict digraph "" {',
 ' edge[len=5];',
 ' node[style=filled];',
 ' overlap=false;',
 ' outputorder=edgesfirst;',
 ' nodesep=0.5;',
 ' packmode="graph";',
 ' subgraph clusterKey {',
 '  clusterrank=local;',
 '  pos="0,0!";',
 '  "Last mesh walk performed at %s by %s" [color=none, fontcolor=black, label="%s\n%s", pos="1,9!"];' % [ ISOTimestamp, Ourselves, ISOTimestamp, Ourselves ],
 '  "White text: JSON status (machine-parseable)" [color=green, fontcolor=white, label="JSON status", pos="1,8!"];',
 '  "Yellow text: HTML status (not machine-parseable)" [color=green, fontcolor=yellow, label="HTML status", pos="1,7!"];',
 '  "Cyan background (white or yellow text): Sync lag (number of keys <99% of expected)" [color=darkcyan, fontcolor=white, label="Not syncing", pos="1,6!"];',
 '  "Red background: Read timeout (overloaded server)" [color=red, fontcolor=black, label="Read timeout", pos="1,5!"];',
 '  "Orange background: Protocol (SSL, HTTP) error" [color=orange, fontcolor=black, label="Protocol error", pos="1,4!"];',
 '  "Yellow background: Network error (could not connect)" [color=yellow, fontcolor=black, label="Network error", pos="1,3!"];',
 '  "Black background: Other error" [color=black, fontcolor=white, label="Other error", pos="1,2!"];',
 '  "Grey background: Missing (no DNS entry or not a keyserver)" [color=grey90, fontcolor=black, label="Missing", pos="1,1!"];',
 '  %s [color=none, fontcolor=black, label="Black lines: sync\nGrey lines: broken sync", pos="1,0!"];' % [MinskyExplanation],
 ' }'
].each { |lin|
  graph lin
  green_graph lin
}

# Clean StartFrom before use; we don't know where PersistentState['INIT'] has been
fork('INIT', filter_peers(StartFrom))
preen_connections()
graph_connections()
graph '}'

# GW: Might seem backwards to generate the green graph from this
# data... but it was actually easier ;-) Sorry to anybody who wants to
# follow my mental processes.
Dot['filehandle'].seek(0)
green_graph greenify(Dot['filehandle'].readlines)
green_graph '}'

Dot['filehandle'].close
GreenDot.close

Log.info('Analysis done. Finishing outputs and rendering.')

File.open(File.join(OutDir, 'walk-sks.yaml'), 'w') {|f| f.puts [Servers, Status].to_yaml }
system(GraphvizBin, '-Tsvg', '-O', Dot['filehandle'].path)
system(GraphvizBin, '-Tsvg', '-O', GreenDot.path)

# Maintain predictable soft links to the latest copy of the output
system('ln', '-sf', File.join(OutDirTimestamp, 'walk-sks.yaml'), SksStatusDir)
system('ln', '-sf', File.join(OutDirTimestamp, 'walk-sks.green.dot.svg'), SksStatusDir)
system('ln', '-sf', File.join(OutDirTimestamp, 'walk-sks.dot.svg'), SksStatusDir)

# Update and save our state cache
PersistentState['meankeys'] = MeanKeys['mean']
PersistentState['aliases'] = HostAliases
File.write(StateCache, JSON.dump(PersistentState))

Log.info('Done!')
