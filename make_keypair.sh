#!/usr/bin/env bash
multikeyjwt --version || pip install --user multikeyjwt
multikeyjwt genkey ./jwtRS256.key
