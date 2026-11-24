#!/bin/bash
cd "$(dirname "$0")"
# waits for the first sweep (c1-http) to finish, then runs the rest in order
while ! grep -q "sweep c1-http done" logs/c1-http.summary 2>/dev/null; do sleep 5; done
./sweep.sh c1-ws 100 111 ws --seconds 30
./sweep.sh c1-grpc 100 111 grpc --seconds 30
for t in http ws grpc; do ./sweep.sh c2-$t-bounded 200 207 $t --seconds 30 --policy bounded-error; done
for t in http ws grpc; do ./sweep.sh c3-$t-unsafe 300 307 $t --seconds 30 --unsafe; done
for t in http ws grpc; do ./sweep.sh c4-$t-2ep 400 407 $t --seconds 30 --endpoints 2; done
for t in http ws grpc; do ./sweep.sh c5-$t-2ep-unsafe-bounded 500 505 $t --seconds 30 --endpoints 2 --unsafe --policy bounded-error; done
for t in http ws grpc; do ./sweep.sh c6-$t-cache 600 605 $t --seconds 30 --cache; done
echo ALL DONE > logs/sweep_all.done
