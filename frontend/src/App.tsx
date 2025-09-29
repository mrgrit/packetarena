// /opt/packetarena/frontend/src/App.tsx
import { useEffect, useState } from "react";
import axios from "axios";

const API = "http://10.20.30.1:8000/api/v1"; // ← 백엔드 IP로 교체

export default function App() {
  const [templates, setTemplates] = useState<any[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [iface, setIface] = useState("eth0");
  const [remoteHost, setRemoteHost] = useState("<SENSOR-IP>"); // ← 센서 IP로 교체

  // ----- handlers (반드시 return 위에 위치) -----
  useEffect(() => {
    axios.get(`${API}/packets`).then((r) => setTemplates(r.data));
  }, []);

  const gen = async (id: string) => {
    const vars: any = {
      src_ip: "203.0.113.10",
      dst_ip: "10.20.50.100",
      dst_port: 80,
      count: 10,
    };
    if (id === "pkt-icmp") delete vars.dst_port;
    const r = await axios.post(`${API}/packets/generate`, {
      template_id: id,
      variables: vars,
    });
    alert(`PCAP: ${r.data.pcap_path}  packets=${r.data.packet_count}`);
  };

  const replay = async () => {
    const p = prompt("pcap_path? (위 Generate 결과값 복사)");
    if (!p) return;
    await axios.post(`${API}/replay/start`, {
      pcap_path: p,
      iface,
      options: { mbps: "10M", loop: 1 },
    });
    alert("replay started");
  };

  const startSSE = () => {
    const es = new EventSource(
      `${API}/logs/suricata/stream?host=${remoteHost}&sudo=false`
    );
    es.onmessage = (e: MessageEvent) => {
      setLogs((prev) => [e.data as string, ...prev].slice(0, 200));
    };
    es.onerror = () => es.close();
  };

  // 1) Rewrite 버튼 UI
  const rewritePcap = async () => {
    const inpath = prompt("Original pcap_path?");
    if (!inpath) return;
    const srcmap =
      prompt('src_ipmap (e.g. "10.0.0.10:192.168.1.100")') || undefined;
    const dstmap =
      prompt('dst_ipmap (e.g. "10.0.0.20:192.168.1.200")') || undefined;
    const r = await axios.post(`${API}/packets/rewrite`, {
      pcap_path: inpath,
      src_ipmap: srcmap,
      dst_ipmap: dstmap,
    });
    alert(`Rewritten: ${r.data.rewritten_pcap}`);
  };

  // 2) Remote Capture UI
  const remoteCapture = async () => {
    const host = prompt("Remote host (sensor or endpoint)?", remoteHost);
    const riface = prompt("Remote iface?", "eth0");
    const dur = Number(prompt("Duration seconds?", "10") || "10");
    if (!host || !riface) return;
    const r = await axios.post(`${API}/remote/capture`, {
      host,
      iface: riface,
      duration: dur,
      sudo: true,
    });
    alert(`Fetched: ${r.data.local_path}`);
  };

  // ----- UI -----
  return (
    <div style={{ padding: 16 }}>
      <h2>PacketArena – Phase 2</h2>

      <h3>Templates</h3>
      <ul>
        {templates.map((t) => (
          <li key={t.id}>
            <b>{t.name}</b> [{t.id}]{" "}
            <button onClick={() => gen(t.id)}>Generate</button>
          </li>
        ))}
      </ul>

      <h3>Replay</h3>
      <div>
        iface:{" "}
        <input value={iface} onChange={(e) => setIface(e.target.value)} />
      </div>
      <button onClick={replay}>Start Replay</button>

      <h3>Rewrite & Remote Capture</h3>
      <button onClick={rewritePcap}>Rewrite PCAP</button>
      <button onClick={remoteCapture} style={{ marginLeft: 8 }}>
        Remote Capture
      </button>

      <h3>Suricata Live (Remote)</h3>
      <div>
        sensor host:{" "}
        <input
          value={remoteHost}
          onChange={(e) => setRemoteHost(e.target.value)}
        />
      </div>
      <button onClick={startSSE}>Start Stream</button>
      <pre
        style={{
          height: 300,
          overflow: "auto",
          background: "#111",
          color: "#0f0",
          padding: 8,
        }}
      >
        {logs.join("\n")}
      </pre>
    </div>
  );
}
