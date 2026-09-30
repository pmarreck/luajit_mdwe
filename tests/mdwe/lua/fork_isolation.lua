-- T5a/T5e/T11: after fork(), neither process's JIT activity may change the
-- other's machine code; the mcode memfd is write-sealed at fork and each side
-- moves to a new memfd before its next write. FFI callbacks made before the
-- fork work in both processes. Exit 0 and prints "fork_isolation: ok ..." on
-- success.
package.path = arg[0]:gsub("[^/]*$", "") .. "?.lua;" .. package.path
local h = require("mdwe_ffi")
local SEAL_WRITE_SHRINK_GROW = 0x02 + 0x04 + 0x08
-- Distinct functions so each compiles its own trace(s).
local function gen(expr)
  return load("return function(k) local s = 0 for i = 1, 100000 do s = s + " .. expr .. " end return s end")()
end
local pre = { gen("(i % k)"), gen("(i * k) % 7"), gen("(i + k) % 5"), gen("bit.band(i, k)") }
local post = { gen("(i * k) % 13"), gen("(i - k) % 3"), gen("bit.bxor(i, k) % 9") }
local function work(k) local s = 0 for _, f in ipairs(pre) do s = s + f(k) end return s end
local function work2(k) local s = 0 for _, f in ipairs(post) do s = s + f(k) end return s end
local expect = {}
for k = 3, 8 do expect[k] = work(k) end
local cb = h.make_cmp()
local snap = h.snapshot()
local fd0, seals0, ino0 = h.mcode_memfd()
-- The harness says which allocator to expect (LJ_EXPECT_REMAP=1), so a run
-- that silently fell back to anonymous mcode fails instead of skipping checks.
local remap = os.getenv("LJ_EXPECT_REMAP") == "1"
local fails = {}
local function check(c, msg) if not c then fails[#fails + 1] = msg end end
if remap then check(fd0 ~= nil, "no mcode memfd before fork") end

local p2c_r, p2c_w = h.pipe()
local c2p_r, c2p_w = h.pipe()
local pid = h.ffi.C.fork()
if pid == 0 then
  local mysnap = h.snapshot()
  if remap then
    local _, seals = h.mcode_memfd()
    check(seals and bit.band(seals, SEAL_WRITE_SHRINK_GROW) == SEAL_WRITE_SHRINK_GROW, "child: memfd not write-sealed after fork")
  end
  h.send(c2p_w); h.wait(p2c_r)            -- parent compiles meanwhile
  check(h.changed(mysnap) == 0, "child: parent's post-fork compile changed child code")
  for k = 3, 8 do check(work(k) == expect[k], "child: wrong result from pre-fork trace") end
  for k = 3, 8 do check(work2(k) == work2(k), "child: compile failed") end
  check(h.sorted(cb) == "12345", "child: pre-fork FFI callback broken")
  if remap then
    local _, seals, ino = h.mcode_memfd()
    check(ino ~= ino0, "child: still on the pre-fork memfd after compiling")
    check(seals and bit.band(seals, 0x02) == 0, "child: new memfd unexpectedly write-sealed")
  end
  io.stdout:write(#fails == 0 and "" or ("child FAIL: " .. table.concat(fails, "; ") .. "\n"))
  io.stdout:flush()
  h.ffi.C._exit(#fails == 0 and 0 or 1)
end
h.wait(c2p_r)
if remap then
  local _, seals = h.mcode_memfd()
  check(seals and bit.band(seals, SEAL_WRITE_SHRINK_GROW) == SEAL_WRITE_SHRINK_GROW, "parent: memfd not write-sealed after fork")
end
for k = 3, 8 do check(work2(k + 10) == work2(k + 10), "parent: compile failed") end
if remap then
  local _, _, ino = h.mcode_memfd()
  check(ino ~= ino0, "parent: still on the pre-fork memfd after compiling")
end
h.send(p2c_w)
local st = h.waitchild(pid)
check(st == 0, "child exited with status " .. st)
check(h.changed(snap) == 0, "parent: child's compile changed parent code")
for k = 3, 8 do check(work(k) == expect[k], "parent: wrong result from pre-fork trace") end
check(h.sorted(cb) == "12345", "parent: pre-fork FFI callback broken")
if #fails > 0 then print("fork_isolation FAIL: " .. table.concat(fails, "; ")) os.exit(1) end
print(("fork_isolation: ok remap=%d traces=%d"):format(remap and 1 or 0, (function() local n = 0 for _ in pairs(snap) do n = n + 1 end return n end)()))
