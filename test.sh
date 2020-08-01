#!/bin/bash 

./build.sh | tail -12 > out.log; diff out.log out.log.orig && echo SUCCESS
