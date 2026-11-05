def scan(line, params)
  1 if line =~ /#/ && eval(params[:c]) # EXPECT: finding
end
