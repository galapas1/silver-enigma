#!/bin/bash -e

function bye() {
	echo 1>&2 $*
	exit 0
}

function die() {
	echo 1>&2 $*
	exit 1
}

NP=`which ninjapanda` || die "didn't find ninjapanda"

RESP=`${NP} health -o json-line`
if [[ "$RESP" == *"\"status\":\"online\""* ]]; then
  bye "$RESP"
fi

die "{\"server\":{\"status\":\"offline\"}}"
