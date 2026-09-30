-- T4: side traces patch exits of parent traces living in a DIFFERENT mcode
-- area. Phase 1 compiles parent loops with one branch cold; filler traces
-- then fill further (small, 8 KB) areas; phase 2 makes the branch hot, so
-- side traces are compiled into newer areas and patch the old parents.
-- Prints "cross_area: pairs=N far=M checksum=C"; exits 1 unless at least one
-- parent/side pair lies at least one area apart.
jit.opt.start("sizemcode=8", "maxmcode=4096", "hotexit=2")
local jutil = require("jit.util")
local parent, pending = {}, {}
-- The parent trace number arrives with "start"; keep it once "stop" confirms.
jit.attach(function(what, tr, func, pc, otr)
  if what == "start" then pending[tr] = (otr and otr > 0) and otr or nil
  elseif what == "stop" and pending[tr] then parent[tr] = pending[tr] end
end, "trace")
local acc = 0
local parents = {}
for k = 1, 8 do
  parents[k] = load(("return function(n, hot) local s = 0 for i = 1, n do if hot and i %% 2 == 0 then s = s + i * %d else s = s + 1 end end return s end"):format(k))()
  acc = acc + parents[k](2000, false)
end
for k = 1, 150 do  -- filler root traces in later areas
  local f = load(("return function(n) local s = 0 for i = 1, n do s = s + (i %% %d) end return s end"):format(k + 2))()
  acc = (acc + f(1000)) % 1000000007
end
for k = 1, 8 do acc = (acc + parents[k](2000, true)) % 1000000007 end
local area = 8 * 1024
local pairs_n, far = 0, 0
for tr, otr in pairs(parent) do
  local _, a = jutil.tracemc(tr)
  local _, b = jutil.tracemc(otr)
  if a and b then
    pairs_n = pairs_n + 1
    if math.abs(a - b) >= area then far = far + 1 end
  end
end
print(("cross_area: pairs=%d far=%d checksum=%d"):format(pairs_n, far, acc))
if far == 0 then os.exit(1) end
