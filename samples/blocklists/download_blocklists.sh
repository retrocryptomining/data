#!/bin/bash

grep -v "#" blocklists/blocklists.txt > tmp
for url in `cat tmp`; do
    TMP=`echo $url | sed 's/.*\/\///g'`
    DIR=`dirname $TMP`
    FILENAME=`basename $TMP`
    EPOCH=`date +%s`
    echo "Epoch: "$EPOCH
    mkdir -p blocklists/$DIR
    pushd blocklists/$DIR
    wget $url
    mv $FILENAME ${EPOCH}_$FILENAME
    popd
done
rm tmp
