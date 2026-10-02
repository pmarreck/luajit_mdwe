-- Review R5: after jit.flush() the mcode memfd must hold no storage, even if
-- the sandbox denies fallocate (hole punching). Compiles traces with varying
-- -Osizemcode across flushes, then prints the memfd's allocated bytes
-- (st_blocks * 512). Prints "flush_storage: bytes=0" when nothing is retained.
package.path = arg[0]:gsub("[^/]*$", "") .. "?.lua;" .. package.path
local h = require("mdwe_ffi")
local ffi = h.ffi
ffi.cdef[[ int fstat(int fd, void *st); ]]
local sizes = { 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64 }
for round, kb in ipairs(sizes) do
  jit.opt.start("sizemcode=" .. kb)  -- Takes effect at the first area after a flush.
  for k = 1, 30 do
    local f = load(("return function(n) local s = 0 for i = 1, n do s = s + i %% %d end return s end")
      :format(round * 100 + k))()
    f(300)
  end
  jit.flush()
end
local fd = assert(h.mcode_memfd(), "no mcode memfd (run with the memfd allocator on)")
local st = ffi.new("uint8_t[256]")
assert(ffi.C.fstat(fd, st) == 0, "fstat")
-- st_blocks is at offset 64 in struct stat on both x86_64 and aarch64 Linux.
local blocks = ffi.cast("int64_t *", st + 64)[0]
print(("flush_storage: bytes=%d"):format(tonumber(blocks) * 512))
