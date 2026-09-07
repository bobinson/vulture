def a
  do_thing
rescue => e
  nil
end
def b
  do_thing
rescue => e
  logger.error("failed: #{e}")
end
def c
  do_thing
rescue => e
  raise
end
