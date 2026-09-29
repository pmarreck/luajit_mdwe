-- Exercises the FFI callback trampoline page (lj_ccallback.c), which is
-- mprotect()ed RX separately from trace mcode and does not check the result.
local ffi = require("ffi")
ffi.cdef[[void qsort(void *base, size_t n, size_t sz, int (*cmp)(const void *, const void *));]]
local a = ffi.new("int[5]", {5, 3, 4, 1, 2})
ffi.C.qsort(a, 5, ffi.sizeof("int"), function(x, y)
  return ffi.cast("const int *", x)[0] - ffi.cast("const int *", y)[0]
end)
print(("sorted=%d%d%d%d%d"):format(a[0], a[1], a[2], a[3], a[4]))
