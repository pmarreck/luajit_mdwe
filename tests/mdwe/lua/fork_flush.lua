-- T5b: the parent flushes (frees, and under a naive design punches) its mcode
-- while the child keeps executing pre-fork traces. The child must survive and
-- compute correct results. Prints "fork_flush: ok".
package.path = arg[0]:gsub("[^/]*$", "") .. "?.lua;" .. package.path
local h = require("mdwe_ffi")
local function f(n) local s = 0 for i = 1, n do s = s + (i % 11) end return s end
local want = f(300000)
local r, w = h.pipe()
local pid = h.ffi.C.fork()
if pid == 0 then
  h.wait(r)
  local ok = true
  for _ = 1, 20 do if f(300000) ~= want then ok = false end end
  h.ffi.C._exit(ok and 0 or 1)
end
jit.flush()
local function g(n) local s = 0 for i = 1, n do s = s + (i % 17) * 2 end return s end
local gv = g(300000)
h.send(w)
local st = h.waitchild(pid)
if st ~= 0 then print("fork_flush FAIL: child status " .. st) os.exit(1) end
print(("fork_flush: ok g=%d"):format(gv))
