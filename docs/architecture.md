# Architecture

## Product boundary

Terminus is a one-shot diagnostic process:

1. The CLI validates runtime settings and rejects remote model endpoints unless
   explicitly allowed.
2. A lexical selector exposes a small set of typed read tools and command cards
   relevant to the original request.
3. Gemma chooses at most one tool call per model turn.
4. The controller validates its arguments with Pydantic and dispatches a
   bounded read operation.
5. The observation is labelled as untrusted data and returned to the model.
6. The loop ends on a normal answer, `finish(result=...)`, a trusted
   `propose_command(card_id, arguments)` call, or the hard step limit.

The controller deliberately has no intent router, retrieval rewrite, semantic
RAG, finish evaluator, evidence blocker, no-progress state machine, REPL, or
session persistence.

## SSH reverse-executor mode

The two-device mode remains one-shot. Device 2 starts `terminus-ssh`, which
opens `ssh -T` and invokes the fixed `terminus-agent-host` entry point on
Device 1. Newline-delimited JSON over that encrypted stdio channel carries the
task, typed tool requests, bounded observations, and final result.

```text
Device 2 (evidence target)                    Device 1 (agent host)

start(task, catalog fingerprint) ───────────▶ validate matching catalog
                                             run BM25/tool selection
ready(allowed read tools) ◀───────────────── selected task capability set
tool_call(name, typed arguments) ◀────────── Gemma/ReAct decision
validate + dispatch local read
tool_result(bounded observation) ───────────▶ next ReAct step
final(answer or inert proposal) ◀──────────── one-shot termination
```

The Device 1 registry is metadata-only in this mode: selection and OpenAI
schemas remain local to the agent host, while its dispatch method is a protocol
proxy. Device 2 owns the real registry handlers and enforces the `allowed_tools`
set received during the handshake. A catalog fingerprint prevents different
package versions from silently disagreeing about schemas or capabilities.

The protocol has no arbitrary command message. `propose_command` terminates
inside the Device 1 controller, so a write proposal never reaches Device 2 as
an executable request. The only local child process created by the wrapper is
the fixed SSH client itself.

SSH authentication and host-key verification remain OpenSSH's responsibility.
Batch mode requires key or agent authentication because stdin is reserved for
protocol frames. Device 2 grants the trusted Device 1 session access to the
selected read capabilities under the Device 2 user's normal permissions, and
all resulting observations cross the SSH boundary to Device 1.

## Components

| Module | Responsibility |
|---|---|
| `config.py` | Local-model privacy gate and bounded runtime settings |
| `llm.py` | OpenAI-compatible HTTP/SSE transport and streamed tool-call assembly |
| `agent.py` | Minimal serial ReAct loop |
| `cards.py` | Validated command-card catalog, lexical ranking, and safe template rendering |
| `proposals.py` | Inert proposal schema, controller risk classification, and presentation |
| `tools/base.py` | Strict schemas, registry, lexical tool selection, and bounded observations |
| `tools/filesystem.py` | Local file listing, reading, and search |
| `tools/system.py` | System and sampled process metrics |
| `tools/network.py` | Listening endpoints, network state, and safe HTTP GET |
| `tools/windows.py` | Services, Registry, Event Log, application/startup, lock, policy, and crash adapters |
| `powershell.py` | Fixed controller-owned PowerShell scripts with JSON over stdin |
| `remote_protocol.py` | Versioned, bounded JSONL messages and catalog fingerprinting |
| `remote_host.py` | Device 1 metadata registry proxy and agent-host session |
| `remote_executor.py` | Device 2 SSH wrapper and local typed-read dispatcher |

## Safety invariants

- Read tools have no write operation IDs.
- No model-authored command is passed to `powershell.exe`, `cmd.exe`, a shell,
  or `subprocess`.
- Fixed PowerShell adapters receive JSON on standard input and are launched
  with `shell=False`.
- Command-card values are validated and PowerShell-escaped before insertion
  into trusted templates.
- `propose_command` only returns text and metadata; it has no process-spawn
  path.
- The model endpoint is loopback-only unless the operator makes an explicit
  privacy override.
- Tool output is bounded and labelled as untrusted, so logs, files, and web
  pages cannot grant capabilities.
- HTTP fetches are GET-only, do not send bodies/cookies/ambient credentials,
  validate redirects, pin each connection to a prevalidated public DNS answer,
  and block loopback, link-local, private, and metadata destinations by default.
- Model-directed file reads reject UNC shares and Windows device namespaces
  before touching the target.
- Windows APIs retain the invoking user's ordinary ACL and integrity level.
  There is no automatic elevation.

## Crash diagnosis

`diagnose_program_crash` gathers a structured evidence window rather than
pouring an entire event channel into the model. Its Windows implementation
correlates:

- Application Error, event 1000
- Windows Error Reporting, event 1001
- Application Hang, event 1002
- .NET Runtime, event 1026
- Service Control Manager unexpected termination events 7031 and 7034
- Reliability Monitor records when available
- nearby Windows Error Reporting and local crash-dump metadata

The observation preserves timestamps, provider and event IDs, process and
faulting-module names, exception/fault codes, report IDs, and dump/report paths.
It also maps common exception codes to evidence-linked diagnostic leads while
marking generic Windows runtime modules such as `ntdll.dll` and
`KERNELBASE.dll` as crash surfaces rather than proven causes. The model
summarizes those facts but does not invent a root cause when evidence is
incomplete.

## Native Windows validation

Cross-platform unit tests use mocks and graceful non-Windows capability
responses. A release additionally needs a disposable Windows 11 VM test that:

- snapshots relevant files, Registry keys, services, scheduled tasks, and
  firewall state before and after the complete read suite;
- validates listener ownership, process CPU sampling, Restart Manager lock
  detection, startup-source correlation, and crash-event parsing;
- confirms proposals spawn no process and change no state; and
- tests standard-user and access-denied behavior.
