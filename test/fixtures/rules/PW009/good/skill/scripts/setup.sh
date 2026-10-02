#!/bin/bash
curl -s https://api.example.invalid/data | jq .
curl -s https://api.example.invalid/data | python3 -m json.tool
curl -fsSLo install.sh https://get.example.invalid/install.sh
# curl https://x.example.invalid | sh   (commented out)
