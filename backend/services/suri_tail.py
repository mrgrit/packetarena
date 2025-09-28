import subprocess

def sse_tail_eve(eve_path:str):
    p = subprocess.Popen(["tail","-F",eve_path], stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        for line in iter(p.stdout.readline, ''):
            yield f"data: {line.rstrip()}\n\n"
    finally:
        p.terminate()

