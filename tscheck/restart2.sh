pkill -f "serve2.mts" ; sleep 0.5
cd /tmp/claude-0/-home-claude/2eef2116-d342-54e0-910e-45ab56c8e52f/scratchpad/tscheck
(PROV=${PROV:-both} nohup node --experimental-sqlite --no-warnings $(npm root -g)/tsx/dist/cli.mjs serve2.mts > serve2.log 2>&1 &)
sleep 3; cat serve2.log
