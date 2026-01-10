import { connect } from 'cloudflare:sockets';

// ============ 硬编码常量 ============
const UUID = new Uint8Array([
  0x55, 0xd9, 0xec, 0x38, 0x1b, 0x8a, 0x45, 0x4b,
  0x98, 0x1a, 0x6a, 0xcf, 0xe8, 0xf5, 0x6d, 0x8c
]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

// 流控阈值
const WS_BACKPRESSURE = 32768;
const MERGE_THRESHOLD = 4096;
const MERGE_WINDOW = 16384;
const BATCH_SIZE = 8;
const CONNECT_TIMEOUT = 2000;

// 预分配常量
const textDecoder = new TextDecoder();
const EMPTY_ARRAY = new Uint8Array(0);
const VLESS_HEADER = new Uint8Array([0x00, 0x00]);

// 响应对象
const R_400 = Object.freeze(new Response(null, { status: 400 }));
const R_403 = Object.freeze(new Response(null, { status: 403 }));
const R_426 = Object.freeze(new Response(null, { status: 426, headers: { Upgrade: 'websocket' } }));
const R_502 = Object.freeze(new Response(null, { status: 502 }));

// ============ Base64 解码 ============
function b64decode(s) {
  let bin;
  try {
    bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return null;
  }
  
  const len = bin.length;
  const out = new Uint8Array(len);
  const end8 = len & ~7;
  
  let i = 0;
  while (i < end8) {
    out[i] = bin.charCodeAt(i);
    out[i+1] = bin.charCodeAt(i+1);
    out[i+2] = bin.charCodeAt(i+2);
    out[i+3] = bin.charCodeAt(i+3);
    out[i+4] = bin.charCodeAt(i+4);
    out[i+5] = bin.charCodeAt(i+5);
    out[i+6] = bin.charCodeAt(i+6);
    out[i+7] = bin.charCodeAt(i+7);
    i += 8;
  }
  while (i < len) {
    out[i] = bin.charCodeAt(i);
    i++;
  }
  
  return out;
}

// ============ UUID 验证 ============
function checkUUID(d, o) {
  return (
    ((d[o]^UUID[0])|(d[o+1]^UUID[1])|(d[o+2]^UUID[2])|(d[o+3]^UUID[3])) === 0 &&
    ((d[o+4]^UUID[4])|(d[o+5]^UUID[5])|(d[o+6]^UUID[6])|(d[o+7]^UUID[7])) === 0 &&
    ((d[o+8]^UUID[8])|(d[o+9]^UUID[9])|(d[o+10]^UUID[10])|(d[o+11]^UUID[11])) === 0 &&
    ((d[o+12]^UUID[12])|(d[o+13]^UUID[13])|(d[o+14]^UUID[14])|(d[o+15]^UUID[15])) === 0
  );
}

// ============ VLESS 解析（修复地址类型） ============
function parseVLESS(d) {
  const len = d.length;
  
  // 版本检查
  if (len < 22 || d[0] !== 0x00) return null;
  
  // UUID 验证
  if (!checkUUID(d, 1)) return null;
  
  // 附加信息长度
  const aLen = d[17];
  if (aLen > 255) return null;
  
  const cOff = 18 + aLen;
  if (cOff + 3 > len) return null;
  
  // 命令检查（只支持 TCP）
  const cmd = d[cOff];
  if (cmd !== 0x01) return null;
  
  // 端口
  const port = (d[cOff+1] << 8) | d[cOff+2];
  const aOff = cOff + 3;
  
  if (aOff >= len) return null;
  
  // 地址类型（修复：1=IPv4, 2=Domain, 3=IPv6）
  const atype = d[aOff];
  let host;
  let end;
  
  if (atype === 0x01) {
    // IPv4
    end = aOff + 5;
    if (end > len) return null;
    const a = d[aOff+1];
    const b = d[aOff+2];
    const c = d[aOff+3];
    const e = d[aOff+4];
    host = `${a}.${b}.${c}.${e}`;
  } else if (atype === 0x02) {
    // Domain
    if (aOff + 2 > len) return null;
    const dLen = d[aOff+1];
    end = aOff + 2 + dLen;
    if (end > len) return null;
    host = textDecoder.decode(d.subarray(aOff+2, end));
  } else if (atype === 0x03) {
    // IPv6（修复：类型是 3 不是 4）
    end = aOff + 17;
    if (end > len) return null;
    const v = new DataView(d.buffer, d.byteOffset + aOff + 1, 16);
    host = [
      v.getUint16(0, false).toString(16),
      v.getUint16(2, false).toString(16),
      v.getUint16(4, false).toString(16),
      v.getUint16(6, false).toString(16),
      v.getUint16(8, false).toString(16),
      v.getUint16(10, false).toString(16),
      v.getUint16(12, false).toString(16),
      v.getUint16(14, false).toString(16)
    ].join(':');
  } else {
    return null;
  }
  
  if (end > len) return null;
  
  return { host, port, off: end };
}

// ============ TCP 连接 ============
async function dial(host, port, fallback) {
  const h = fallback ? PROXY_HOST : host;
  const p = fallback ? PROXY_PORT : port;
  const sock = connect({ hostname: h, port: p }, { allowHalfOpen: false });
  
  let tid;
  await Promise.race([
    sock.opened,
    new Promise((_, rej) => { tid = setTimeout(rej, CONNECT_TIMEOUT); })
  ]);
  clearTimeout(tid);
  
  return sock;
}

// ============ 状态机 ============
function State(ws, tcp) {
  this.ws = ws;
  this.tcp = tcp;
  this.dead = false;
}

State.prototype.kill = function() {
  if (this.dead) return;
  this.dead = true;
  try { this.ws.close(); } catch {}
  try { this.tcp.close(); } catch {}
};

// ============ 上行：智能合并 ============
function Uplink(s, w) {
  this.s = s;
  this.w = w;
  this.q = [];
  this.b = 0;
  this.busy = false;
}

Uplink.prototype.push = function(chunk) {
  if (this.s.dead) return;
  
  const size = chunk.length;
  
  // 队列过载保护
  if (this.q.length > 31 || this.b > 262144) {
    this.s.kill();
    return;
  }
  
  this.q.push(chunk);
  this.b += size;
  
  // 触发条件：大包或缓冲满
  if (!this.busy && (size > MERGE_THRESHOLD || this.b >= MERGE_WINDOW)) {
    this.drain();
  } else if (!this.busy) {
    const self = this;
    queueMicrotask(() => self.drain());
  }
};

Uplink.prototype.drain = function() {
  if (this.busy || this.s.dead || this.q.length === 0) return;
  
  this.busy = true;
  const q = this.q;
  const total = this.b;
  
  // 提取全部队列
  const batch = q.splice(0, q.length);
  this.b = 0;
  
  let payload;
  if (batch.length === 1) {
    payload = batch[0];
  } else {
    payload = new Uint8Array(total);
    let off = 0;
    for (let i = 0; i < batch.length; i++) {
      const c = batch[i];
      payload.set(c, off);
      off += c.length;
    }
  }
  
  const s = this.s;
  const w = this.w;
  const self = this;
  
  w.ready.then(() => {
    if (s.dead) return;
    return w.write(payload);
  }).then(() => {
    self.busy = false;
    if (self.q.length > 0 && !s.dead) {
      self.drain();
    }
  }).catch(() => s.kill());
};

// ============ 下行：流式传输 ============
function Downlink(s, ws, r) {
  this.s = s;
  this.ws = ws;
  this.r = r;
  this.first = true;
  
  this.run();
}

Downlink.prototype.run = function() {
  const s = this.s;
  const ws = this.ws;
  const r = this.r;
  let first = this.first;
  
  (async () => {
    try {
      while (!s.dead) {
        // 背压控制
        if (ws.bufferedAmount > WS_BACKPRESSURE) {
          await new Promise(res => {
            const check = () => {
              if (ws.bufferedAmount < WS_BACKPRESSURE || s.dead) {
                res();
              } else {
                queueMicrotask(check);
              }
            };
            check();
          });
        }
        
        if (s.dead) break;
        
        // 批量读取
        for (let i = 0; i < BATCH_SIZE && !s.dead; i++) {
          const { done, value } = await r.read();
          
          if (done || s.dead) {
            s.kill();
            return;
          }
          
          // 首帧处理
          if (first) {
            const frame = new Uint8Array(value.length + 2);
            frame.set(VLESS_HEADER, 0);
            frame.set(value, 2);
            ws.send(frame);
            first = false;
          } else {
            ws.send(value);
          }
          
          // 提前退出
          if (ws.bufferedAmount > WS_BACKPRESSURE) break;
        }
      }
    } catch (err) {
      s.kill();
    } finally {
      try { r.releaseLock(); } catch {}
    }
  })();
};

// ============ 主入口 ============
export default {
  async fetch(req) {
    if (req.headers.get('Upgrade') !== 'websocket') return R_426;
    
    const proto = req.headers.get('Sec-WebSocket-Protocol');
    if (!proto) return R_400;
    
    const data = b64decode(proto);
    if (!data) return R_400;
    
    const vless = parseVLESS(data);
    if (!vless) return R_403;
    
    // 连接 TCP（带回退）
    let tcp;
    try {
      tcp = await dial(vless.host, vless.port, false);
    } catch {
      try {
        tcp = await dial(vless.host, vless.port, true);
      } catch {
        return R_502;
      }
    }
    
    // WebSocket 握手（修复：使用标准解构）
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    
    const state = new State(server, tcp);
    
    // 初始数据
    const initial = data.length > vless.off ? data.subarray(vless.off) : EMPTY_ARRAY;
    
    // 建立管道
    const up = new Uplink(state, tcp.writable.getWriter());
    if (initial.length > 0) up.push(initial);
    
    server.addEventListener('message', e => up.push(new Uint8Array(e.data)));
    server.addEventListener('close', () => state.kill());
    server.addEventListener('error', () => state.kill());
    
    new Downlink(state, server, tcp.readable.getReader());
    
    return new Response(null, { status: 101, webSocket: client });
  }
};
