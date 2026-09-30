-- T6 (P2): whenever a trace has just been committed, and at exit, no
-- writable mapping of the mcode memfd may exist. Prints
-- "maps_audit: checks=N writable=0 rx=K".
local function scan()
  local w, rx = 0, 0
  for line in io.lines("/proc/self/maps") do
    if line:find("memfd:luajit%-mcode") then
      local perms = line:match("^%S+%s+(%S+)")
      if perms:sub(2, 2) == "w" then w = w + 1 end
      if perms:sub(3, 3) == "x" then rx = rx + 1 end
    end
  end
  return w, rx
end
local checks, writable = 0, 0
jit.attach(function(what)
  if what == "stop" then
    local w = scan()
    checks = checks + 1
    writable = writable + w
  end
end, "trace")
local acc = 0
for k = 1, 60 do
  local fn = load(("return function(n) local s=0 for i=1,n do if i%%%d==0 then s=s+i else s=s+1 end end return s end"):format(k % 5 + 2))()
  acc = acc + fn(3000)
end
jit.attach(function() end)
local w, rx = scan()
writable = writable + w
print(("maps_audit: checks=%d writable=%d rx=%d"):format(checks, writable, rx))
if writable ~= 0 or checks == 0 or rx == 0 then os.exit(1) end
