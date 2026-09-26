import json
import urllib.request
import urllib.error
import subprocess
import time
import os
import re
from pathlib import Path

class Server:
    def __init__(self, port: str):
        self.port = port
        self.alias = 'Unknown'
        self.process = None
        self.param = -1
        self.quantization = -1


    def check_model_running(self):
        url = f"http://127.0.0.1:{self.port}/v1/models"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.load(response)

            print("Currently running:")

            for model in data.get('data', []):
                self.alias = model['id']
                print(f" - {model['id']}")
            
            return True
            
        except urllib.error.URLError as error:
            print('No model is currently running')
            print(f'Error: {error}')

        return False


    def start_model_server(self):
        if self.check_model_running():
            return None

        directory = Path.home() / "models" / "llm"
        model = ''
        sizes = []
        
        ls_output = os.listdir(directory)
        
        for llm in ls_output:
            match = re.search(r"^Ornith.*gguf$", llm)
            if match:
                model = directory / llm
                break
            else:
                param = int(re.search(r"\dB", llm).group()[0])
                sizes.append(param)
        
        if not model:
            indexed = list(enumerate(sizes))
            indexed.sort(key=lambda x : x[1])

            model = directory / ls_output[indexed[0][0]]
            self.param = indexed[0][1]
            quant = re.search(r"Q\d", model)
            if quant:
                self.quantization = int(quant.group()[-1])
            
        if self.alias == 'Unknown':
            self.alias = model.stem.split("-")[0]
            
        
        command = [
            "llama-server",
            "-m", str(model),
            "-ngl", "999",
            "-c", "8192",
            "--host", "127.0.0.1",
            "--port", str(self.port),
            "--alias", str(self.alias),
            "--jinja",
            "--reasoning-format", "none",
            "--repeat-penalty", "1.15",
            "--repeat-last-n", "512",
            "--temp", "0",
            "--dry-multiplier", "0.8",
            "--dry-base", "1.75",
            "--dry-allowed-length", "2",
        ]

        log_directory = Path(os.getenv("LOCALAPPDATA", ".")) / "Terminus"
        log_directory.mkdir(parents=True, exist_ok=True)

        log_path = log_directory / "llama-server.log"
        log_file = log_path.open("ab", buffering=0)

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP
                    | subprocess.DETACHED_PROCESS
                ),
                close_fds=True,
            )
        finally:
            log_file.close()
        timeout = 45 + 4.125 * self.quantization * self.param if self.quantization != -1 and self.param != -1 else 120
        deadline = time.monotonic() + 120

        while time.monotonic() < deadline:
            exit_code = process.poll()

            if exit_code is not None:
                raise RuntimeError(f"llama server exited with code {exit_code}")
            
            url = f"http://127.0.0.1:{self.port}/v1/models"

            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    data = json.load(response)

                models = data.get("models", data.get("data", []))

                model_names = {
                    item.get("name") or item.get("id") or item.get("model")
                    for item in models
                }

                if self.alias in model_names:
                    print(f"Model {self.alias} is ready")
                    self.process = process
                    return True

            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                pass

            time.sleep(0.5)

        if process.poll() is None:
            process.terminate()
            process.wait()

        raise TimeoutError(
            f"Model did not load within {timeout} seconds"
        )



    def stop_model_server(self):
        if self.process is None:
            print("No model process exists")
            if self.check_model_running:
                return self.stop_server_on_port(self.port)
            return False

        if self.process.poll() is not None:
            print(f"Model {self.alias} is already stopped")
            self.process = None
            return False

        self.process.terminate()

        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("Model did not stop normally; forcing shutdown")
            self.process.kill()
            self.process.wait()

        print(
            f"Model {self.alias} running on port "
            f"{self.port} has stopped"
        )

        self.process = None
        return True

    
    def stop_server_on_port(self, port: int) -> bool:
        port = int(port)

        powershell_script = f"""
    $connections = @(
        Get-NetTCPConnection `
            -LocalPort {port} `
            -State Listen `
            -ErrorAction SilentlyContinue
    )

    if ($connections.Count -eq 0) {{
        Write-Error "Nothing is listening on port {port}"
        exit 1
    }}

    $pids = @(
        $connections |
        Select-Object -ExpandProperty OwningProcess -Unique
    )

    foreach ($serverPid in $pids) {{
        $process = Get-Process -Id $serverPid -ErrorAction Stop

        if ($process.ProcessName -ne "llama-server") {{
            Write-Error "Port {port} belongs to $($process.ProcessName), not llama-server"
            exit 2
        }}
    }}

    foreach ($serverPid in $pids) {{
        Stop-Process -Id $serverPid -Force
        Write-Output "Stopped llama-server PID $serverPid on port {port}"
    }}
    """

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                powershell_script,
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(result.stderr.strip())
            return False

        print(result.stdout.strip())
        return True

        



