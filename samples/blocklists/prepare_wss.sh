# Takes a list of ws/wss patterns from common blocklists and transforms them into the kind of pattern that our regexes will search for (more specific)

WSFILE=$1
cat $1 | sed 's/.*\/\///g' | sed 's/\*$//g' | sed 's/\/$//g' | sed 's/^/wss:\/\//g'
