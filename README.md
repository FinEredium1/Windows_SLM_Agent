# Terminus for Windows

Terminus is a local, one-shot Windows diagnostic assistant. It uses a small
Gemma-class model through a loopback llama.cpp endpoint, a bounded ReAct loop,
typed read-only tools, and trusted PowerShell command cards.

One invocation handles one request:

```text
natural-language request
        ↓
Gemma chooses one typed read tool
        ↓
bounded Windows observation
        ↓
Gemma answers, reads again, or selects a trusted command card
        ↓
grounded answer OR unexecuted PowerShell proposal
```

There is no REPL, conversation memory, semantic RAG, arbitrary PowerShell
executor, or automatic write path.

## Initial workflows

```powershell
terminus "Show me all the ports that are listening right now"
terminus "Check CPU usage for process widget.exe"
terminus "I cannot delete C:\Apps\Widget. Find what is using it and why that process starts"
terminus "Why did widget.exe crash? Check the recent logs"
terminus "How do I set PowerShell execution policy to run scripts?"
```

The last request returns a risk-labelled command suggestion such as a
current-user `RemoteSigned` policy change. Terminus does **not** execute it.

## Requirements

- Windows 11 for the first supported release
- Python 3.11 or newer
- A local OpenAI-compatible llama.cpp server
- A roughly 4B-class instruction/tool-use model with a working tool-enabled
  chat template

The defaults preserve the KISS model contract:

- API: `http://127.0.0.1:11434/v1`
- Model API name: `gemma`
- Temperature: `0`
- Thinking: disabled
- ReAct limit: 12 model steps
- Model context target: 12,288 tokens

Model weights and `llama-server.exe` are not downloaded or bundled by this
repository.

## Install

From PowerShell in the repository:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\terminus.exe --help
```

This form does not require activating the virtual environment or changing the
PowerShell execution policy.

Start an existing llama.cpp server with the included launcher:

```powershell
.\deploy\windows\start-llama.ps1 `
  -ServerPath C:\Models\llama-server.exe `
  -ModelPath C:\Models\gemma-4-E2B-it-qat-UD-Q4_K_XL.gguf
```

If policy blocks the `.ps1` wrapper, no policy change is required just to start
the model. Run the executable directly from an interactive PowerShell prompt:

```powershell
& 'C:\Models\llama-server.exe' `
  -m 'C:\Models\gemma-4-E2B-it-qat-UD-Q4_K_XL.gguf' `
  --host 127.0.0.1 --port 11434 -c 12288 --temp 0 --jinja
```

Leave that foreground server running. In a second PowerShell window, run:

```powershell
.\.venv\Scripts\terminus.exe "Show me all listening TCP ports"
```

Useful options:

```text
--base-url URL
--model NAME
--max-steps N
--top-k N
--no-stream
--allow-remote-model
--verbose
--debug
--json
--version
```

Terminus refuses a non-loopback model URL by default because observations can
contain private file, process, Registry, or Event Log data. The
`--allow-remote-model` switch is an explicit privacy opt-in.

## Two-device SSH mode

Use the SSH wrapper when the model and agent loop run on Device 1 but the
Windows evidence must come from Device 2:

```text
Device 2                                      Device 1
terminus-ssh + typed read executor ──SSH──▶ BM25 + Gemma + ReAct
                                tool call ◀──┤
                        local observation ──▶│
                              final answer ◀─┘
```

Install the same Terminus version on both devices. On Device 1, keep the local
llama.cpp endpoint running and make `terminus-agent-host` available in the
non-interactive SSH account's `PATH`. Device 2 needs only the installed Python
package and an OpenSSH client; it does not need model weights or a model
server. On Device 2, establish the host key and SSH key/agent authentication
first, then run:

```powershell
.\.venv\Scripts\terminus-ssh.exe user@device1 `
  "Show me all the ports that are listening right now"
```

If the Device 1 entry point is not on `PATH`, supply a shell-safe executable
path without spaces or metacharacters. Absolute POSIX paths and forward-slash
Windows paths such as
`C:/Terminus/.venv/Scripts/terminus-agent-host.exe` are accepted:

```powershell
.\.venv\Scripts\terminus-ssh.exe user@device1 `
  --remote-command /opt/terminus/.venv/bin/terminus-agent-host `
  "Why did widget.exe crash? Check the recent logs"
```

This is deliberately different from opening an interactive shell and running
`terminus` there: a normal SSH command executes its tools on Device 1. The
`terminus-ssh` wrapper owns the SSH standard-input/output channel and executes
only schema-validated, read-only tools on Device 2. Device 1 performs command
card BM25 selection and every model/ReAct step.

The task is sent as JSON over SSH stdin, never interpolated into a remote shell
command. Device 2 verifies that both installations have the same tool catalog
and permits only the small tool set selected on Device 1 for that task.
Suggested write commands are returned to Device 2 for review and are never
executed by the local executor.

SSH mode sends the selected Device 2 observations to Device 1 and its local
model. Use it only when Device 1 is trusted to receive that data. The wrapper
uses SSH batch mode because protocol data owns stdin, so password
authentication is not supported.

## Read capabilities

- Filesystem listing, bounded text reading, and content search
- System and process information, including sampled per-process CPU
- Listening TCP/UDP ports with owning process IDs
- Windows services and process-startup sources
- File/application deletion blockers
- Registry, installed applications, and execution-policy state
- Windows Event Log and structured program-crash correlation
- Network configuration
- Size- and destination-bounded public HTTP GET

Every tool runs with the current user's permissions. Terminus does not bypass
Windows ACLs, protected processes, encryption, or Group Policy. UNC shares and
Windows device namespaces are deliberately excluded from model-directed file
reads.

## Write-command proposals

Write suggestions are compiled from packaged command-card templates. The model
selects a card ID and supplies schema-validated values; it cannot send raw
PowerShell to an execution function. The resulting proposal includes the exact
command, effect, risk, elevation requirement, warnings, and rollback when one
is defined. Its structured result always contains:

```json
{"executed": false}
```

## Development

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

The cross-platform suite validates the controller, card compiler, safety
policy, and platform-independent tools. Native Event Log, Registry, Restart
Manager, service, and startup-source behavior must also pass in a disposable
Windows 11 VM before release.

See [docs/architecture.md](docs/architecture.md) for the component and safety
boundaries.
