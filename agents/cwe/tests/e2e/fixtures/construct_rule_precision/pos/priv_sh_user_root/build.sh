#!/bin/sh
docker run --user root -v "$PWD":/src builder make  # EXPECT: finding
