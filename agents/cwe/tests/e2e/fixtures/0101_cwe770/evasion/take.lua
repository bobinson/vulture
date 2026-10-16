function drain(sock)
  local t = {}
  while true do
    local line = sock:receive("*l")
    if not line then break end
    -- EXPECT-NEXT: clean known-gap: Lua t[#t+1]; the shared stripper reads # as a comment (LLD 5.2.6) (probe:E37 Lua table append via length index)
    t[#t + 1] = line
  end
  return t
end
