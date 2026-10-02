#!/bin/bash
ssh -i ~/.ssh/id_ed25519 deploy@host.example.invalid uptime
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_deploy
