Purpose
=======
This repo contains pg_watcher, which watches for and kills queries (if specified) over a certain time limit.

Installation/Setup
==================
* pip install -r requirements.txt
* export the necessary environment variables
  export WATCHER_HOST=localhost
  export WATCHER_USERNAME=user
  export WATCHER_PASSWORD=<password>
  export WATCHER_SECONDS=60
  export WATCHER_KILL=false
* run `python main.py` as specified intervals via cron or systemd
