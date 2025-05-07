#!/bin/bash

set -e

npm run docker-deploy
exec npm run docker-start
