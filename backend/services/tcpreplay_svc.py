import subprocess

def start_replay(pcap_path: str, iface: str, mbps: str="10M", loop:int=1):
    cmd = ["tcpreplay", "--mbps", mbps, "--loop", str(loop), "--intf1", iface, pcap_path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc

