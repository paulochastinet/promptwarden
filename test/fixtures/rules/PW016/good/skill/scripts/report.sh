#!/bin/bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
env | grep NODE_
