-- Deterministic trace-heavy workload: many small loops with type- and
-- branch-varying bodies force traces, side traces and exit patching.
-- Prints a checksum so runs can be compared across builds.
local compiled, aborted = 0, 0
if jit.status() then
  jit.attach(function(what) if what == "stop" then compiled = compiled + 1 elseif what == "abort" then aborted = aborted + 1 end end, "trace")
end
local n = tonumber(arg and arg[1]) or 200
local acc = 0
for k = 1, n do
  local f = load(("local k=%d return function(m) local s=0 for i=1,m do if i%%%d==0 then s=s+i*k elseif i%%3==0 then s=s-(i/%d) else s=s+1 end end return s end"):format(k, (k % 5) + 2, k))()
  for rep = 1, 3 do acc = (acc + f(2000 + rep)) % 1e9 end
end
print(("churn n=%d compiled=%d aborted=%d checksum=%.3f"):format(n, compiled, aborted, acc))
