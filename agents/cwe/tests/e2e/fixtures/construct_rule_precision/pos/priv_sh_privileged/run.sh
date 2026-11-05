#!/bin/sh
docker run --privileged -v /:/host alpine sh  # EXPECT: finding
