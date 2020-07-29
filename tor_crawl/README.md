# Contents

This directory contains results for scanning Tor exit nodes for injection. Author: Nathan S. Evans <nathan.s.evans at du.edu>.
 
The methodology for this scan is incredibly simple (naive?).

 Step 1: Grab a static web page from somewhere on the Internet. Calculate the MD5 hash of the content.
 Step 2: Using STEM, grab all valid exit nodes from Tor, and fetch the same static page via each exit.
 Step 3: If the hash of the page fetched via Tor is different than the original, save the content.
 Step 4: Check the different hashes to see if they include cryptojacking software. 
         NOTE on step 4: Originally the goal was to have this step be automated, but since the 
                         vast majority of exits don't tamper with content (at least in our testing)
                         we did this checking manually. However, there is a script that does it as 
                         well.

result files contain csv file output from the tor_fetch_all* python program running once a day. 

example_result.csv:
  A simple comma separated values file showing what the output of the above python program looks like.
  Outputs one line per exit node tested and the MD5 of the page fetched.

miner_md5s.txt:
  Collection of the md5 sums of pages fetched that were found to include cryptomining software. Not
  all of these were collected via Tor, some were found using open proxy lists.

hashes:
  Directory containing the data fetched from responses that did not match the expected hash output. Vast majority
  of these hashes are FPs due to network issues, Tor issues, or who knows what else.
