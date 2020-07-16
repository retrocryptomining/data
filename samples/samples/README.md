Script file names contain the time in epochs at which they were found.
Directories generally indicate the site/domain that uses the miner in
particular.  See README.md inside for details, where applicable. Also listing
the miner type below.


authedmine/
Mining scripts by authedmine, a Coinhive miner.
Generally obfuscated; some deobfuscated ones stored in plaintext/.


browsermine/
A Coinhive injector.


coin-hive/
A npm implementation of coinhive. Available from github.
https://github.com/cazala/coin-hive


coinhave/
A cryptonight implementation. Obfuscated, but simple base64 decoding gives
the cryptonight miner.


coinhive/
Mining scripts + simple-ui.min.js. The latter is actually pulled from
authedmine.com.
Can get mining statistics for a known key:
curl https://api.coinhive.com/user/balance?name=john-doe&amp;secret=&lt;secret-key&gt;


cryptonight/cryptonoter:
cryptonight seems to be the successor to cryptonoter. Used by many sites.
http://minero.pw/miner.min.js
adless
minero.pw

cryptonoter is a miner from https://github.com/jamesmeyer1993/CryptoNoter;
seems to have moved to https://github.com/cryptonoter, which uses webminerpool.
Uses processor.js, worker.js and cryptonight-asmjs.min.js,
cryptonight-asmjs.min.js.mem, cryptonight.wasm. Uses proxy - e.g.
mutuza.win/proxy. Seems to work with several pools, e.g.  webminerpool and
cryptonote-universal-pool. Site https://www.cryptonoter.com does not work any
more.



coinrail:
https://coinrail.io/
https://www.coinrail.io/lib/coinrail.min.js

deepminer:
Independent miner. Available from https://github.com/deepwn/deepMiner
Uses deepMiner.min.js.
Relies on cryptonight-asmjs.min.js and cryptonight-asmjs.min.js.mem, but those
are implementations of the cryptonote (later called cryptonight) protocol.


gridcash:
Formerly adless, gridcash.net. Signed up as Hans Pumpernickle.


webminepool:
base.js - a cryptonight implementation
helper.js
All options explained on https://webminepool.com/page/js-miner


webminerpool:
Uses webmr.js. cryptonight/cryptonight-lite based. Relationship to webminepool
unclear.

webxmr/
Implementation from webxmr.com. Closed beta now.




Non-JS-based miners:
afminer

Could not connect and retrieve samples for:
Papoto
Coinerra
afminer
ppoi.org - no wonder, Google blocks as "unsafe"
minemytraffic
