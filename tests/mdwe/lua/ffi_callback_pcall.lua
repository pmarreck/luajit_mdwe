-- FFI callback creation must either yield a working callback or raise a
-- catchable error; it must never hand out a non-executable trampoline.
-- Prints "cb=ok sorted=12345" or "cb=error <message>".
local ffi = require("ffi")
ffi.cdef[[void qsort(void *base, size_t n, size_t sz, int (*cmp)(const void *, const void *));]]
local ok, cb = pcall(ffi.cast, "int (*)(const void *, const void *)", function(x, y)
  return ffi.cast("const int *", x)[0] - ffi.cast("const int *", y)[0]
end)
if not ok then print("cb=error " .. tostring(cb)) return end
local a = ffi.new("int[5]", {5, 3, 4, 1, 2})
ffi.C.qsort(a, 5, ffi.sizeof("int"), cb)
print(("cb=ok sorted=%d%d%d%d%d"):format(a[0], a[1], a[2], a[3], a[4]))
