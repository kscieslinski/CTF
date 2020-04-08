# Collection (150 pts, 30 solves)
[behold my collection](files/52ae03f0ae030a74a2bd466852308cba74c0f313.tar.gz)

The container is built with the following important statements

FROM ubuntu:18.04
RUN apt-get -y install python3.6
COPY build/lib.linux-x86_64-3.6/Collection.cpython-36m-x86_64-linux-gnu.so /usr/local/lib/python3.6/dist-packages/Collection.cpython-36m-x86_64-linux-gnu.so
Copy the library in the same destination path and check that it works with

python3.6 test.py
Challenge runs at 35.207.157.79:4444

Difficulty: easy