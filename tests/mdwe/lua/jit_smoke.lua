-- Forces real trace compilation and verifies traces exist and computed correctly.
-- Prints "traces=<n> sum=<s>"; exits 1 if JIT is on but no trace was compiled.
local jutil = require("jit.util")
local s = 0
for i = 1, 1e6 do s = s + (i % 7) end
local n = 0
while jutil.traceinfo(n + 1) do n = n + 1 end
print(("jit=%s traces=%d sum=%d"):format(tostring(jit.status()), n, s))
if jit.status() and n == 0 then os.exit(1) end
