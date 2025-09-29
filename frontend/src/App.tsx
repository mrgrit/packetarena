import { useEffect, useState } from "react";
import axios from "axios";

const API = "http://<BACKEND-IP>:8000/api/v1"; // <- 백엔드 VM IP로 교체

export default function App() {
  const [templates, setTemplates] = useState<any[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [iface, setIface] = useState("eth0");
  const [remoteHost, setRemoteHost] = useState("10.20.50.21");

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
    es.onmessage = (e: any) =>
      setLogs((prev) => [e.data, ...prev].slice(0, 200));
    es.onerror = () => es.close();
  };

  return (
    <div style={{ padding: 16 }}>
      <h2>PacketArena – Phase 1</h2>

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

