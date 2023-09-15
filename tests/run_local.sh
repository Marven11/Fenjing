export VULUNSERVER_ADDR="http://127.0.0.1:5000"
export SLEEP_INTERVAL=0.05
python vulunserver.py 2>/dev/null &
vulserver_pid=$!
python -m unittest *.py
kill $vulserver_pid