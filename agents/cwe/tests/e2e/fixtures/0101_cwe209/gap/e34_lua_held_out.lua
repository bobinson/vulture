local ok, err = pcall(run)
if not ok then
  -- EXPECT-NEXT: clean  known-gap lua held out
  ngx.say(err)
end
