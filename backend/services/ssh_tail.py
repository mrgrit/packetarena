import paramiko

def sse_tail_eve_remote(host:str, user:str, keyfile:str, eve_path:str, sudo:bool=False):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, key_filename=keyfile, timeout=10)
    try:
        chan = client.get_transport().open_session()
        cmd = f"sudo -n tail -F {eve_path}" if sudo else f"tail -F {eve_path}"
        chan.exec_command(cmd)
        with chan.makefile("r") as f:
            for line in f:
                yield f"data: {line.rstrip()}\n\n"
                if chan.exit_status_ready():
                    break
    finally:
        client.close()

