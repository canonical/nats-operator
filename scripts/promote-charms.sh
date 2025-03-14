#!/bin/bash -e
#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#

from=
to=
charm="nats"
dry_run=false
arch=amd64
series=jammy

while [ -n "$1" ]; do
    case "$1" in
        --from=*)
            from=${1#*=}
            shift
            ;;
        --to=*)
            to=${1#*=}
            shift
            ;;
        --series=*)
            series=${1#*=}
            shift
            ;;
        --arch=*)
            arch=${1#*=}
            shift
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        *)
            echo "No positional arguments allowed"
            exit 1
            ;;
    esac
done

if [ -z "$from" ] || [ -z "$to" ]; then
    echo "ERROR: --from and --to are required"
    exit 1
fi

base=unknown
case "$series" in
  jammy)
    base=22.04
    ;;
  noble)
    base=24.04
    ;;
  *)
    echo "ERROR: Unsupported series $series"
    exit 1
    ;;
esac

rev="$(charmcraft status "$charm" --format=json | \
    jq ".[].mappings[] | select(.base.channel == \"$base\" and .base.architecture == \"$arch\") | .releases[] | select(.channel == \"$from\") | .revision")"
if [ "${dry_run}" = false ]; then
    extra_args=
    resources="core nats"
    [ ! -e zero-size-resource ] && touch zero-size-resource
    for r in $resources ; do
        output=$(charmcraft upload-resource "$charm" "$r" --format=json --filepath zero-size-resource 2>/dev/null | tail -n3)
        rrev=$(echo "$output" | jq .revision)
        extra_args="$extra_args --resource $r:$rrev"
    done
    charmcraft release -q "$charm" -r "$rev" -c "$to" $extra_args
fi
echo "Released revision $rev for charm $charm on base $series to channel $to"
