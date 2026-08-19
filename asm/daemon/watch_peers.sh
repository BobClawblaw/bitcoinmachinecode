#!/usr/bin/env bash
# Labeled live view of outbound peer connections to the bitcoind download worker.
while true; do
  clear
  echo "PEER STATUS  ($(date '+%Y-%m-%d %H:%M:%S'))"
  echo
  printf "%-18s %-8s %-20s\n" "PEER" "UNREAD" "STATUS"
  printf "%-18s %-8s %-20s\n" "----" "------" "------"
  ss -tnp state established 2>/dev/null | grep 8333 | while read -r recvq sendq local peer proc; do
    ip=$(echo "$peer" | cut -d: -f1)
    kb=$((recvq / 1024))
    if [ "$kb" -gt 100 ]; then
      status="BACKLOGGED (not draining)"
    elif [ "$kb" -gt 0 ]; then
      status="receiving"
    else
      status="idle / caught up"
    fi
    printf "%-18s %-8s %-20s\n" "$ip" "${kb}KB" "$status"
  done
  echo
  echo "UNREAD = bytes the peer sent that we haven't processed yet."
  echo "         Large + not shrinking = we're falling behind that peer."
  sleep 2
done
