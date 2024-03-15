export VULUNSERVER_ADDR="http://127.0.0.1:5000"
export SLEEP_INTERVAL=0.01
targets="*.py"
if [ "$1" != "" ]; then
  targets="$1"
fi
python vulunserver.py 2>/dev/null &
vulserver_pid=$!
trap "trap - SIGTERM && kill $vulserver_pid" SIGINT SIGTERM EXIT
python -m unittest $targets
