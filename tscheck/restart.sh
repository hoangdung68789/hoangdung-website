pkill -f serve.mts; sleep 0.5
cd /tmp/claude-0/-home-claude/2eef2116-d342-54e0-910e-45ab56c8e52f/scratchpad/tscheck
cp ../deploy/app/src/server/api.server.ts src/server/
(MIG=../deploy/app/migrations/0001_init.sql nohup node --experimental-sqlite --no-warnings $(npm root -g)/tsx/dist/cli.mjs serve.mts > serve.log 2>&1 &)
sleep 3
