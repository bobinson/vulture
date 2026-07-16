package provider
import ("encoding/json";"os";"strings";"testing")
func TestZZBigReqDiag(t *testing.T){
  key:=os.Getenv("GEMINI_DIAG_KEY"); tj:=os.Getenv("TOOLS_JSON")
  if key==""||tj==""{t.Skip("need keys")}
  raw,_:=os.ReadFile(tj)
  var dump []struct{Name string `json:"name"`; Schema map[string]any `json:"schema"`}
  json.Unmarshal(raw,&dump)
  var tools []ToolDef
  for _,d:=range dump{tools=append(tools,ToolDef{Type:"function",Name:d.Name,Parameters:d.Schema})}
  // large source-like context (~1.5MB text ~ 375k tokens, well under 1M)
  big:=strings.Repeat("def handler(req):\n    x = eval(req.body)  # CWE-95\n    return x\n",20000)
  for _,sz:=range []struct{n string;p string}{
    {"small","scan"},
    {"big-user",big},
  }{
    req:=CompletionRequest{Model:"gemini-2.5-flash",
      Messages:[]Message{{Role:"system",Content:"You are a security auditor. Return findings."},{Role:"user",Content:sz.p}},
      Tools:tools,MaxTokens:8192,Temperature:0,HasTemperature:true}
    st,body:=postGeminiLive(t,key,buildGeminiRequest(req))
    if len(body)>300{body=body[:300]}
    t.Logf("%s (len=%d): status=%d body=%s",sz.n,len(sz.p),st,body)
  }
}
