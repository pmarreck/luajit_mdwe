-- Shared FFI helpers for the MDWE fork/seal tests (Linux).
local ffi = require("ffi")
local jutil = require("jit.util")
ffi.cdef[[
int fork(void);
int waitpid(int pid, int *status, int options);
void _exit(int status);
int pipe(int fds[2]);
int close(int fd);
long read(int fd, void *buf, unsigned long n);
long write(int fd, const void *buf, unsigned long n);
long readlink(const char *path, char *buf, unsigned long n);
int fcntl(int fd, int cmd, ...);
void qsort(void *base, size_t n, size_t sz, int (*cmp)(const void *, const void *));
]]
local M = {}
local F_GET_SEALS = 1034

-- fd, seals and inode of this process's LuaJIT mcode memfd (nil if none).
function M.mcode_memfd()
  local buf = ffi.new("char[256]")
  for fd = 0, 1023 do
    local n = ffi.C.readlink("/proc/self/fd/" .. fd, buf, 255)
    if n > 0 and ffi.string(buf, n):find("memfd:luajit%-mcode", 1, false) then
      local f = io.open("/proc/self/fdinfo/" .. fd)
      local info = f and f:read("*a") or ""
      if f then f:close() end
      return fd, ffi.C.fcntl(fd, F_GET_SEALS), tonumber(info:match("ino:%s*(%d+)"))
    end
  end
end

-- Snapshot of the machine code bytes of every live trace.
function M.snapshot()
  local s, t = {}, 1
  while jutil.traceinfo(t) do
    local mc = jutil.tracemc(t)
    if mc then s[t] = mc end
    t = t + 1
  end
  return s
end

-- Number of traces whose bytes differ from a snapshot.
function M.changed(snap)
  local n = 0
  for t, mc in pairs(snap) do
    if jutil.tracemc(t) ~= mc then n = n + 1 end
  end
  return n
end

function M.pipe()
  local p = ffi.new("int[2]")
  assert(ffi.C.pipe(p) == 0)
  return p[0], p[1]
end
function M.send(fd) assert(ffi.C.write(fd, "x", 1) == 1) end
function M.wait(fd) local b = ffi.new("char[1]"); assert(ffi.C.read(fd, b, 1) == 1, "peer exited before the handshake") end
function M.waitchild(pid)
  local st = ffi.new("int[1]")
  assert(ffi.C.waitpid(pid, st, 0) == pid)
  return st[0]
end

-- A comparison callback, created by the caller (before or after fork).
function M.make_cmp()
  return ffi.cast("int (*)(const void *, const void *)", function(a, b)
    return ffi.cast("const int *", a)[0] - ffi.cast("const int *", b)[0]
  end)
end
function M.sorted(cb)
  local a = ffi.new("int[5]", {5, 3, 4, 1, 2})
  ffi.C.qsort(a, 5, 4, cb)
  return ("%d%d%d%d%d"):format(a[0], a[1], a[2], a[3], a[4])
end

M.ffi = ffi
return M
