#!/usr/bin/env bash

NAME="tinkernels/simple-mail-forwarder"
TAG='' && [ -n "$1" ] && TAG=":$1" && shift

docker push "$NAME$TAG"
