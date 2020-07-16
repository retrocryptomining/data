// We follow the order in the _keywords files.
// General construction rules:
// - Pick from most common keywords as per _keywords file (usually top 3-4)
// - manual inspection of JS file for particular keywords
// Good luck.


// TODO: the MonerominerrocksDeob may be unnecessary - as far as I can tell,
// the miner does not contain obfuscation keywords, and hence this would never
// be sent to the deobfuscator.

// =========================================================================
// PLAINTEXT SCRIPTS
// These are scripts that are not obfuscated.
// =========================================================================

/*
 * Match adless.js
 */
rule Adless {

    meta:
        description = "Match adless.js artefacts"
        author = "mrwigglet,ralph" // who to blame
        date = "2018-07-22"

    strings:
        // STATUS: confirmed
        $a = "miner" nocase
        $b = "params" nocase
        $c = "prototype" nocase
        $d = "adless" nocase
        $e = "CRYPTONIGHT_WORKER_BLOB" nocase
        $f = "CONFIG.REQUIRES_AUTH" nocase

    condition:
        all of them
}



/*
 * Match lib-asmjs.min.js
 */

rule Adlessasm {

   meta:
       description = "Match adless asm"
       author = "ralph"
       date = "2018-07-22"

   strings:
       $a = "module" nocase
       $b = "ret" nocase
       $d = "length" nocase
       $e = "cryptonightwasmwrapper" nocase
       $f = "stacktop" nocase
       $g = "statictop" nocase
       $h = "memoryinitializer" nocase
       $i = "adless" nocase
   condition:
       all of them

}



/*
* Match authedmine (commonalities)
*/

rule AuthedmineHelperPlain {
	meta:
		description = "Match Authedmine commonalities (such as simple-ui), plaintext"
		author = "ralph"
		date = "2018-07-26"

	strings:
        $a = "throttle" nocase
        $b = "CoinHive.CONFIG" nocase
        $c = "onCoinHiveSimpleUIReady" nocase
        $d = "settimeout" nocase
        $e = "tokenmatch" nocase

	condition:
		all of them
}



/*
 * Match browsermine (commonalities)
 */
rule browsermine {
  meta:
      description = "browsermine - common keywords"
      author = "ralph"
      date = "2018-07-26"

   strings:
      // common
      $a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" nocase
      $b = "0x0" nocase
      $c = "atob" nocase
      $d = "\\x22" nocase
      $e = "\\x20" nocase
      $f = "throttle" nocase
      $g = "0x8" nocase
      $h = "0x7" nocase
      $i = "!function" nocase
      $j = "0x3" nocase
      $k = "slice" nocase
      $l = "charcodeat" nocase
      $m = "0x6" nocase
      $n = "0x10" nocase
   condition:
      all of them
}


/*
 * Match coin-hive
 */
rule coindashhive {

    meta:
        description = "Match coin-hive"
        author = "mrwigglet,ralph"

    strings:
        $a = "miner" nocase
        $b = "message" nocase
        $c = "window" nocase
        $d = "emitmessage" nocase
        $e = "acceptedhashes" nocase
        $f = "hashespersecond" nocase
        $g = "getautothreadsenabled" nocase
        $h = "CoinHive" nocase

    condition:
        all of them
}





/*
 * Match coinblind
 */
rule coinblind {

    meta:
        description = "Match coinblind"
        author = "ralph"
        date = "2018-07-22"

    strings:
        $a = "node" nocase
        $b = "module" nocase
        $c = "path" nocase
        $d = "stream" nocase
        $e = "length" nocase
        $f = "prototype" nocase
        $h = "CoinBlind" nocase

    condition:
        all of them
}



/*
 * Match CoinHive artefacts
 */
rule CoinHive {

    meta:
       description = "Match CoinHive artefacts"
       author = "conand,ralph"
       date = "2018-07-26"

    strings:
        // common keywords
        $a = "sitekey" nocase
        $b = "coinhive" nocase
        $c = "miner" nocase
        $d = "settimeout" nocase
	$e = "throttle"
	// specific ones
	// 1516333897_coinhive.min.js, 1524060000_c-hive.js, 1524060000_coinhive.min.js, 1524060000_coinhive.min_2018-01-19.js, 1531373606_coinhive.min.js
	$g = "outidx" nocase
	$h = "autothreads" nocase
	$i = "hashespersecond" nocase
	$j = "!module" nocase
        $k = "CoinHive.User" nocase
        $l = "CoinHive.CONFIG" nocase
        // mark difference to other miners
        $q = "WMP.CONFIG.LIB_URL"
    condition:
	($a and $b and $c and $d and $e and $g and $h and $i and $j and $k and $l) and (not $q)
}




/*
 * Match CoinHive helper artefacts
 */
rule CoinHiveHelper {

    meta:
       description = "Match CoinHive helper artefacts"
       author = "conand,ralph"
       date = "2018-07-26"

    strings:
        // these are for coinhive helpers, e.g. simple-ui.js
        $g = "throttle" nocase
        $h = "toutcstring" nocase
        $i = "sitekey" nocase
        $j = "settimeout" nocase
        $k = "match" nocase
        // mark difference to other miners
        $q = "Minero"

    condition:
        ($g and $h and $i and $j and $k) and (not $q)
}




/*
 * Match coinpot
 */
rule coinpot {

    meta:
        description = "Match coinpot artefacts"
        author = "mrwigglet,ralph"
        date = "2018-07-22"

    strings:
        $a = "elements" nocase
        $b = "minerui" nocase
        $c = "hashespersecond" nocase
        $d = "coinhive" nocase
        $e = "didaccepthash" nocase

    condition:
        all of them
}



/*
 * Match coinrail
 */
rule CoinRail {

    meta:
        description = "Match coinrail artefacts"
        author = "mrwigglet,ralph"
        date = "2018-07-22"

    strings:
        $a = "CoinRail"
        $b = "CRYPTONIGHT_WORKER_BLOB"
        $c = "node"
        $d = "module"
        $e = "path"

    condition:
        all of them
}




/*
 * Match CryptoLoot
 */
rule CryptoLoot {

    meta:
        description = "Match cryptoLoot artefacts"
        author = "mrwigglet,ralph"
        date = "2018-07-26"

    strings:
        // 1509022800_cryptonight-asmjs.min.js or 1509022800_miner.min.js
        $a = "CryptoLoot.CONFIG" nocase
        $b = "CRYPTONIGHT_WORKER_BLOB" nocase
        // a few miners are very similar to Cryptoloot:
        $h = "Minero"
        $i = "mutuza.win"
        $j = "WMP.CONFIG"
        $k = "webxmr"
        $l = "WMP.User"
        $m = "authedmine.com"
        $n = "deepMiner"

    condition:
	($a or $b) and (not $h) and (not $i) and (not $j) and (not $k) and (not $l) and (not $m) and (not $n)
}




/* 
 * Match CryptoLoot helper
 */
rule CryptoLootHelper {

    meta:
        description = "Match cryptoLoot helper artefacts"
        author = "mrwigglet,ralph"
        date = "2018-07-26"
  
    strings:
        // miner-ui and minui
        $c = "minerui" nocase
        $d = "setinterval" nocase
        $e = "clearinterval" nocase
        $f = "hashespersecond" nocase
        $g = "math" nocase
        // a few miners are very similar to Cryptoloot:
        $h = "Minero"
        $i = "mutuza.win"
        $j = "WMP.CONFIG"
        $k = "webxmr"
        $l = "WMP.User"
        $m = "authedmine.com"
        $n = "deepMiner"

    condition:
        ($c and $d and $e and $f and $g) and (not $h) and (not $i) and (not $j) and (not $k) and (not $l) and (not $m) and (not $n)
}



/*
 * Match unknown Cryptonight
 */
rule CryptonightUnknown {

    meta:
        description = "Match unknown cryptonight"
        author = "mrwigglet,ralph"
        date = "2018-07-26"

    strings:
        // 1509022800_cryptonight-asmjs.min.js or 1509022800_miner.min.js
        $a = "CryptoLoot.CONFIG" nocase
        $b = "CRYPTONIGHT_WORKER_BLOB" nocase
        // a few miners are very similar:
        $h = "Minero"
        $i = "mutuza.win"
        $j = "WMP.CONFIG"
        $k = "webxmr"
        $l = "WMP.User"
        $m = "authedmine.com"
        $n = "deepMiner"
	$o = "loot" nocase

    condition:
	($a or $b) and (not $h) and (not $i) and (not $j) and (not $k) and (not $l) and (not $m) and (not $n) and (not $o)
}



/*
 * Match Cryptonoter
 */
rule Cryptonoter {

    meta:
        description = "Match cryptonoter"
        author = "ralph"
        date = "2018-07-27"

    strings:
	$a = "hashespersecond" nocase
	$b = "throttle" nocase
	$c = "cryptonoter" nocase
	$d = "math" nocase
	$e = "postmessage" nocase
	$f = "nonce" nocase
        // a few miners are very similar:
        $h = "Minero"
        $i = "mutuza.win"
        $j = "WMP.CONFIG"
        $k = "webxmr"
        $l = "WMP.User"
        $m = "authedmine.com"
        $n = "deepMiner"
	$o = "loot" nocase

    condition:
	$a and $b and $c and $d and $e and $f and (not $h) and (not $i) and (not $j) and (not $k) and (not $l) and (not $m) and (not $n) and (not $o)
}




/*
 * Match deepMiner
 */
rule deepMiner {

    meta:
        description = "Match deepMiner artefacts"
        author = "mrwigglet,ralph"
        date = "2018-07-22"

    strings:
        $a = "deepMiner.CONFIG" nocase
        // asm
        $b = "_cryptonight_hash"
        $c = "_cryptonight_create"
        $d = "_cryptonight_destroy"
        // min.js
        $e = "deepMiner.IF_EXCLUSIVE_TAB"
        $f = "deepMiner.VERSION"
        $g = "deepMiner.FORCE_EXCLUSIVE_TAB"
        $h = "deepMiner.FORCE_MULTI_TAB"
        $i = "CRYPTONIGHT_WORKER_BLOB"

    condition:
        $a and ( ($b and $c and $d) or ($e and $f and $g and $h and $i) )
}




/*
 * Match Minero artefacts
 */
rule Minero {

    meta:
       description = "Match Minero artefacts. Does not detect the ASM."
       author = "conand,ralph"
        date = "2018-07-22"

    strings:
        // js
        $a = "Minero.IF_EXCLUSIVE_TAB" nocase
        $b = "now.sh" nocase
        $c = "Minero.BLOB" nocase
        $d = "acceptedHashes" nocase
        $e = "trackingdelegate" nocase

    condition:
        all of them
}



/*
 * Match Minero ASM
 * Problem: I got a feeling this may be very generic ASM, used in many miners.
 */
rule MineroASM {

    meta:
       description = "Match Minero ASM."
       author = "ralph"
        date = "2018-07-22"

    strings:
        // js
        $a = "CryptonightWASMWrapper.prototype.bytesToHex" nocase
        $b = "CryptonightWASMWrapper.prototype.workThrottled"
        $c = "hashesPerSecond:hashesPerSecond,hashes:this.throttledHashes"
        $d = "CryptonightWASMWrapper.prototype.setJob"
        $e = "_cryptonight_hash"

    condition:
        all of them
}




/*
 * Match Monerominer.rocks artefacts
 */
rule Monerminerrocks {

    meta:
       description = "Match Monerominer.rocks artefacts. Does not detect the ASM (not unique enough)."
       author = "ralph"
        date = "2018-07-22"

    strings:
        // js
        $a = "monero.hashvault.pro" nocase
        $b = "throttle_val" nocase
        $c = "stopMining" nocase
        $d = "deactivateminer" nocase

    condition:
        all of them
}


/*
 * Match mutuza.win artefacts
 */
rule MutuzaCryptonight {

    meta:
       description = "Match MutuzaCryptonight."
       author = "ralph"
        date = "2018-07-22"

    strings:
        // processor.js
        $a = "mutuza" nocase
        $b = "CryptoNoter" nocase
        $c = "CRYPTONIGHT_WORKER_BLOB" nocase
        // worker.js
        $e = "CryptoNoter.CONFIG.LIB_URL"
        $f = "node"
        $g = "module"
        $h = "CryptonightWASMWrapper"
        $i = "workThrottled"


    condition:
        $a and ( ($b and $c) or ( $e and $f and $g and $h and $i ) )
}



/*
 * Match webminepool artefacts
 */
rule Webminepool {

    meta:
       description = "Match Webminepool artefacts."
       author = "ralph"
        date = "2018-07-22"

    strings:
        $a = "WMP.CONFIG" nocase
        // main
        $b = "getHashesPerSecond" nocase
        $c = "WMP.IF_EXCLUSIVE_TAB"
        $d = "WMP.FORCE_EXCLUSIVE_TAB"
        $e = "WMP.FORCE_MULTI_TAB"
        $f = "CRYPTONIGHT_WORKER_BLOB"
    condition:
        all of them
}



/*
 * Match webminepool helper artefacts
 */
rule WebminepoolHelper {

    meta:
       description = "Match Webminepool helper artefacts."
       author = "ralph"
       date = "2018-07-26"

    strings:
        // helper
        $g = "CryptonightWASMWrapper.prototype.hash"
        $h = "CryptonightWASMWrapper.prototype.workThrottled"
        $i = "_cryptonight_hash"
        $j = "hashesPerSecond"
	$k = "WMP.FORCE_EXCLUSIVE_TAB"
    condition:
        $g and $h and $i and $j and (not $k)
}


/*
* Match webminepool helper (worker)
*/

rule WebminepoolWorker {

    meta:
       description = "Match Webminepool worker artefacts."
       author = "ralph"
       date = "2018-07-26"

    strings:
        // this imports the actual miner
        $a = "importScripts('cn.js')"
        $b = "cryptonight"
        $c = "postMessage(JSON.stringify(msg))"
        $d = "getRandomInt(0, 0xFFFFFFFF)"
        $e = "function hex2int(s)"
    condition:
        all of them
}


/*
* Match webminepool helper (miner.js)
*/

rule WebminepoolHelperMiner {

    meta:
       description = "Match Webminepool helper miner artefacts."
       author = "ralph"
       date = "2018-07-26"

    strings:
        $a = "totalhashes"
        $b = "wss://"
        $c = "var server"
        $d = "var throttleMiner"
        $e = "var receiveStack"
        $f = "new WebSocket"
        $g = "var wantsToStart"
        $h = "startBroadcast"
        $i = "function startMiningWithId"
        $j = "addWorkers"
        $k = "function informWorker"
        $l = "sendStack.push"
    condition:
        all of them
}


/*
 * Match webxmr artefacts
 */
rule Webxmr {

    meta:
       description = "Match Webxmr artefacts."
       author = "ralph"
       date = "2018-07-22"

    strings:
        $a = "hasownproperty" nocase
        $b = "DYNAMICTOP_PTR" nocase
        $c = "throttle" nocase
        $d = "webxmr" nocase
        $e = "cryptonight_hashnonce" nocase
        $f = "_cryptonight_setblob"
    condition:
        all of them
}


/*
 * Match general Cryptonoter
 */
rule GeneralCryptonoter {

    meta:
        description = "Match general cryptonoter miner"
        author = "ralph"
       date = "2018-07-22"

    strings:
        // general strings
        $a = "CryptoNoter" nocase
        // processor.js
        $b = "CRYPTONIGHT_WORKER_BLOB" nocase
        $c = "miner" nocase
        $d = "params" nocase
        $e = "sitekey" nocase
        $f = "_hashes" nocase
        $g = "_threats" nocase
        // worker.js
        $h = "CryptoNoter.CONFIG"
        $i = "node"
        $j = "module"
        $k = "path"
        $l = "errno_codes"
        $m = "stream"

    condition:
      ($a and ( ($b and $c and $d and $e and $f and $g) or ($h and $i and $j and $k and $l and $m) ) )

}

/*
 * Match general cryptonight
 */
rule GeneralCryptonight {

    meta:
        description = "Match general cryptonight miner"
        author = "ralph"
       date = "2018-07-22"

    strings:
        $a = "module"
        $b = "prototype"
        $c = "outidx"
        $d = "statictop"
        $e = "stacktop"
        $f = "cryptonightwasmwrapper"
        $g = "outu8array"
        $h = "hash"
        $i = "math"

    condition:
        all of them
}





// =========================================================================
// OBFUSCATED SCRIPTS
// We only need rules for those JS that would not be captured by our
// triggers for deobfuscation, i.e. there is no point to write rules if
// these JS contain atob(, eval(, etc. They will be deobfuscated anyway, so 
// we write special rules for after deobfusation. Here, we only deal with
// those that do not contain obfuscation keywords, and hence need rules
// that work on the obfuscated code.
// =========================================================================

// authedmine: no - is deobfuscated
// cloudcoins: no - is deobfuscated
// coinhave: no - is deobfuscated
// coinhive: no - obfuscated scripts are really binary
// coinimp: no - is deobfuscated; but add it anyway due to its difficult obfuscation
// coinnebula: no - is deobfuscated
// cryptoloot:  most scripts are deobfuscated, except below
// - 22800 - miner-ui - not feasible, use fuzzy hash
// - 36800 - crlt.js - not feasible, use fuzzy hash
// - 36800 - mixform - not feasible, use fuzzy hash
// - 60000 - crlt.js - not feasible, use fuzzy hash
// deepminer: no - is deobfuscated
// gridcash: no - is deobfuscated
// monerominer.rocks: no - can also be found after deobfuscation


// coinimp: infeasible? we can try
rule Coinimp {
    meta:
       description = "Match Coinimp (obfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
        // common
        $a = "fHNBCCHN"
        $b = "0aABLIHI"
        $c = "0dKXCNYDBC"
        $d = "1fKWWPV"
        $e = "1cowqqU"
        $f = "dEnSB_WJOOdE{YNfJBEWJOOdEbEB_WJOOdE"
        $g = "String.fromCharCode"
        // variant 1
        $h = "WjggdhtedenWBEX"
        // variant 2
        $i = "YNGDJONOmBGNWHYNJ_NgJQq"

    condition:
        ($a and $b and $c and $d and $e and $f and $g) and ($h or $i)

}






rule JSECoinObfu {

    meta:
       description = "Match JSECoin (obfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
        $a = "safe_add" nocase
        $b = "jsecoin" nocase
        $c = "privacytranslations" nocase
        $d = "hashnonce" nocase
        $e = "localstorage" nocase
        $f = "blockprehash" nocase
        $g = "prehash" nocase
        $h = "difficulty" nocase
        $i = "!important" nocase
        $j = "jsetrack" nocase

    condition:
        all of them
}


rule MonerominerrocksObfu {

    meta:
       description = "Match Monerominerrocks (obfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
        $a = "xmrmining" nocase
        $b = "logicalProcessors" nocase
        $c = "hardwareConcurrency" nocase
        $d = "startMining" nocase
        $e = "readbinary" nocase
        $f = "wasmmemory" nocase
        $g = "webassembly" nocase
        $h = "tempdouble" nocase

    condition:
        all of them
}

rule WebminepoolObfu {
    meta:
       description = "Match Webminepool (obfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
        // base.js
        $a = "WMP.User" nocase
        $b = "WMP.Anonymous" nocase
        $c = "wmtech" nocase
        $d = "getHashesPerSecond" nocase
        $e = "hardwareConcurrency" nocase
        $f = "logicalprocessors" nocase
        $g = "readbinary" nocase
        $h = "wasmmemory" nocase
        $i = "tempdouble" nocase
        // cn.js - not specific enough - try fuzzy hash
        // webmr.js - not specific enough - try fuzzy hash - but detected as general miner

    condition:
        all of them

}


// =========================================================================
// DEOBFUSCATED SCRIPTS
// =========================================================================


rule AuthedmineDeob {
    meta:
       description = "Match Authedmine (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$a = "authedmine.com" nocase
	$b = "CoinHive.CONFIG" nocase
	$c = "CRYPTONIGHT_WORKER_BLOB" nocase
	$d = "CoinHiveOptIn" nocase
	$e = "getTotalHashes" nocase
	$f = "CoinHiveOptOut"
	$g = "getThrottle"
	$h = "getHashesPerSecond"
    condition:
	all of them

}


rule CloudcoinsDeob {
    meta:
       description = "Match Cloudcoins (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$a = "cloudcoins" nocase
        $b = "CLOUDCOINS.KNIGHT_WORKER" nocase
        $c = "CLOUDCOINS.IF_EXCLUSIVE_TAB" nocase
	$d = "CLOUDCOINS.FORCE_EXCLUSIVE_TAB"
	$e = "CLOUDCOINS.FORCE_MULTI_TAB"
	$f = "getThrottle" nocase
	$g = "prototype.didOptOut" nocase
	$h = "hashespersecond" nocase
    condition:
        all of them

}


rule CoinhaveDeob {
    meta:
       description = "Match Coinhave (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$a = "_totalHashesFromDeadThreads" nocase
	$b = "BroadcastChannel" nocase
	$c = "IF_EXCLUSIVE_TAB" nocase
	$d = "getThrottle" nocase
	$e = "CRYPTONIGHT_WORKER_BLOB" nocase
	$f = "FORCE_MULTI_TAB" nocase
	$g = "coinhave" nocase
    condition:
        all of them

}

// coinimp: infeasible? we can try
rule CoinimpDeob {
    meta:
       description = "Match Coinimp (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
        $a = "fHNBCCHN"
        $b = "dIBNX@HCY"
        $c = "dIHNBIH"
        $d = "fHpwwXwwxvqqU"
        $e = "1eipwqqU"
        $f = "dEnSB_WJOOdE{YNfJBEWJOOdEbEB_WJOOdE"
        $g = "WjggdhtedenWBEX[NH_WONHDONWt"
        $h = "String.fromCharCode"

    condition:
        all of them

}


// coinnebula: infeasible? we can try
rule CoinnebulaDeob {
    meta:
       description = "Match Coinnebula (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$a = "wpHCuMOtZERiIMO4P8OIw48W" nocase
	$b = "w5ccYcOqw4MxS2cDClvCucOvwpnDksOLwqzDkX/Dr8KJ" nocase
	$c = "MsOww6EYKC9KK8OkworDhXfCiwQcw53CvsOUwqDCryvCrjgxw4dcJw==" nocase
	$d = "eWnDigbDkw3DrcKuDUclwqzCi8KWwpvDixUWwrwNd8OCwpxWXcOvwopdwqXClWDDvy/Du8KVFsK8VxV0WTHClMOhKQ1BI1/CkMO8w60tw5poXA7DrRITUAHCpsOSwrFRNsKKw4YewqjChQEdwp/CgsKEw5bDgVJKcMOLOH9b" nocase
	$e = "ConQ7DcOPT8KawobDsRQlwrPDh8KWwrjCtsKOWHTDhcK6JQXDuA4qfMOZEUwUw4fCpcKNYl4GWMOYw58Ob8KBw5UNWylrw5xOw7BcbcOYBkbDn2gROMOAwqfCs19OYxLCtTFPeTJNwrPDkcKSFcKNcB3Cn8OzZ8OAQljDj8Kyw"
	$f = "eh40wqfCuQ8zw70EWDAow4xyfsKE"

    condition:
        all of them

}


// Cryptoloot is also very hard
rule CryptolootDeob {
    meta:
       description = "Match Cryptoloot (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$g = "_cryptonight_create" nocase
	// crltasm.min.js/crlt.js
	$h = "_cryptonight_hash" nocase
	$i = "_cryptonight_destroy" nocase
	$j = "CryptonightWASMWrapper" nocase
	// 1524060000_crlt.js.deob is strange
	$k = "CRLT" nocase
	$l = "cryptaloot"
	$m = "CRYPTONIGHT_WORKER_BLOB"
	$n = "justdoit"
	$o = "hardwareConcurrency"
	// mixfork
	$p = "meetsTarget"
	$q = "destroy"
	$r = "cryptaloot"
	$s = "CRLT"
	$t = "cryptonight_hash_impl"
	$u = "mixfork"
	// crypta.js
	$v = "_verifyThread"
	$w = "_totalHashesFromDeadThreads"
	
    condition:
        ($g and $h and $i and $j) or ($k and $l and $m and $n and $o) or ($i and $p and $q and $r and $s and $t and $u) or ($m and $o and $v and $w)
}


// Cryptoloot minui deob
rule CryptolootMinuiDeob {
    meta:
       description = "Match Cryptoloot minui (deobfuscated)"
       author = "ralph"
       date = "2018-07-26"

    strings:
	// min-ui
	$a = "threadsAdd" nocase
	$b = "CryptoLoot.FORCE_MULTI_TAB" nocase
	$c = "MinerUI.prototype.addThread" nocase

    condition:
        all of them
}




// This is after AES decryption...
rule deepMinerDeob {
    meta:
       description = "Match deepMiner (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$a = "deepMiner.IF_EXCLUSIVE_TAB" nocase
	$b = "siteKey" nocase
	$c = "deepMiner.CONFIG" nocase
	$d = "CRYPTONIGHT_WORKER_BLOB" nocase
	$e = "deepMiner.FORCE_EXCLUSIVE_TAB" nocase
	$f = "deepMiner.FORCE_MULTI_TAB" nocase
	$g = "deepMiner.CRYPTONIGHT_WORKER_BLOB"

    condition:
	all of them

}


// gridcash: infeasible? let's try
rule GridcashDeob {
    meta:
       description = "Match Gridcash (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	// Variant 1
	$a = "wptkw5XCsMKLw5PClG3DmDfCr8O/PMOb" nocase
	$b = "W8Kfw5YiOcOaHH1LKMOKw5PCnMOAcn3CkTHDiFMdwqw=" nocase
	$c = "HFrCmQ3CuMKDwqzDqjbCisKuKlEnGRbCtx7DgRjCmMO2w5DCrwvCjMKQwqnCrV3DvjzDoSwNw64=" nocase
	$d = "wrvCi8Ofw67Cki4dJh3DhQV1wpJwwpdUwpIcw6/CgHVvw456HsOdwpgHw6zDkMK5w6Q=" nocase
	$e = "wqV0w4LCtMKPw47Cgn3DojzCh8OjLcONwqk4wpx"
	// Variant 2
	$f = "ADXDmFwGeMOew47DrcK+wp82U8KIw7gTZA4ra8Otw6xkw6fCgcKKwpbDlVFzw7nDjw==" nocase
	$g = "w4LChsO5w73CosOCwonDpWwkw6nCjTHCp1sAwq0XPBTDnsKHdsOmR8K5wooWEsO3" nocase
	$h = "wqPDlEInw5RAAcOdL8KzEsKdw5AH" nocase
	$i = "I8Ojw7LDrcOOw4bDlgolwrZfwo/CicK0woI=" nocase
	$j = "wrEzw4LDr8O6w7LCoMOJwobCosKgcsO+BQ==" nocase

    condition:
        ($a and $b and $c and $d and $e) or ($f and $g and $h and $i and $j)

}



// monerominerrocks

rule MonerominerrocksDeob {
    meta:
       description = "Match Monerominerrocks (deobfuscated)"
       author = "ralph"
       date = "2018-07-22"

    strings:
	$a = "xmrminingproxy" nocase
	$b = "hardwareConcurrency" nocase
	$c = "stopMining" nocase
	$d = "throttleMiner" nocase

    condition:
        all of them
}



/*
* Match deob webminepool helper (worker)
*/

rule WebminepoolDeobHelperWorker {

    meta:
       description = "Match Webminepool helper artefacts (deobfuscated)."
       author = "ralph"
       date = "2018-07-22"

    strings:
        // this imports the actual miner
        $a = "importScripts('cn.js')"
        $b = "Module.cwrap"
        $c = "zeroPad"
        $d = "postMessage(JSON.stringify(msg))"
        $e = "getRandomInt(min, max)"
        $f = "function hex2int(s)"
    condition:
        all of them
}





// =========================================================================
// UNSUCESSFULLY DEOBFUSCATED SCRIPTS
// These are JS that resist our deob attempts - we add some Yara rules here
// to catch the nasty ones.
// =========================================================================

// TODO: since we get only bytes out of this one, we cannot confirm it's a
// true positive. We might take it out from our samples - it's a file that
// has the right filename, and that's why we included it at some point, but
// we have no stronger confirmation.
rule CoinhiveFailedDeob {
    meta:
        description = "Match obfuscated Coinhive in the form of 1520427600_coinhive.js.ourcode.deob"
        author = "ralph"
       date = "2018-07-22"

    strings:
        $a = "ALA0ETAQosRToNBRMCCAcsRQkcAwYTAV1vFkkNQxEVBhcwHxwJCE84Ghc+GRE"
        $b = "TRxM+GQQUHkhLHQs2GEsmHwQEBg0xDgYNPwQTGxpiWExDTwQVGwwtSVhEUBVJ"
        $c = "GhA6BgcVFE8qDA4wGRxQRBoqBgcqBwAiTxEVAA0rLhcLTzxPSw0wSwsYGQgRD"
        $d = "48ChEaBUkCQBg2DU1YCE8EBgc6QhERHw4QSQZkHw0LAhZHBwYoSyMqQyQVGw0"

    condition:
        all of them
}


// =========================================================================
// Other miners for which we have only Yara rules
// TODO: deactivate? We do not have test samples
// =========================================================================


/*
 * Match CWM (CoinWebMiner?)
 */
rule CWM {

    meta:
        description = "Match CWM Artifacts"
        author = "mrwigglet"
       date = "2018-07-21"

    strings:
        $a = "CWM.Anonymous" nocase
        $b = "CWM.User" nocase

    condition:
        $a or $b
}

/*
 * Match NFMiner
 */
rule NFMiner {

    meta:
        description = "Match NFMiner Artifacts"
        author = "mrwigglet"
       date = "2018-07-21"

    strings:
        $a = "NFMiner" nocase

    condition:
        $a
}

/*
 * Match BTCPlusMiner
 */
rule BitcoinPlusMiner {

    meta:
        description = "Match BitcoinPlus Artifacts"
        author = "mrwigglet"
       date = "2018-07-21"

    strings:
        $a = "BitcoinPlusMiner" nocase

    condition:
        $a
}


/*
 * Match inwemo
 */
rule inwemo {

    meta:
        description = "Match inwemo Artifacts"
        author = "mrwigglet"
       date = "2018-07-21"

    strings:
        $a = "inwemo.min.js" nocase
        $b = "website_it" nocase

    condition:
        $a and $b
}


/*
 * Match ProjectPoi
 */
rule ProjectPoi {

    meta:
        description = "Match ProjectPoi Artifacts"
        author = "mrwigglet"
       date = "2018-07-21"

    strings:
        $a = "ProjectPoi.Anonymous" nocase
        $b = "ProjectPoi.User" nocase
        $c = "ProjectPoi" nocase

    condition:
        $a or $b or $c
}
