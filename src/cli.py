"""One-shot Terminus command-line interface."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from . import __version__
from .agent import ReactAgent
from .config import Settings
from .errors import TerminusError
from .llm import LocalModelClient
from .tools import build_default_registry

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help=(
        "Ask one natural-language Windows question. Terminus may perform "
        "typed read-only diagnostics or return an unexecuted PowerShell proposal."
    ),
)


def _version_callback(value: bool) -> bool:
    """Handle --version before Typer validates the required task argument."""
    if value:
        typer.echo(__version__)
        raise typer.Exit()
    return value


@app.command()
def run(
    task: Annotated[
        list[str],
        typer.Argument(help="The natural-language Windows request."),
    ],
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="OpenAI-compatible llama-server base URL."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model name sent to llama-server."),
    ] = None,
    max_steps: Annotated[
        int | None,
        typer.Option("--max-steps", min=1, max=30, help="Hard ReAct step limit."),
    ] = None,
    top_k: Annotated[
        int | None,
        typer.Option(
            "--top-k",
            min=1,
            max=8,
            help="Number of read tools and command cards exposed to the model.",
        ),
    ] = None,
    no_stream: Annotated[
        bool,
        typer.Option("--no-stream", help="Use a non-streaming model response."),
    ] = False,
    allow_remote_model: Annotated[
        bool,
        typer.Option(
            "--allow-remote-model",
            help="Allow Windows observations to be sent to a non-loopback endpoint.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show the tool trace and token usage."),
    ] = False,
    assistant: Annotated[
        bool,
        typer.Option("--assistant", "-a", help="Use for just chatting directly with the model"),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            help="Dump model request payloads; may expose diagnostic data.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the structured result as JSON."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Print the Terminus version and exit.",
        ),
    ] = False,
) -> None:
    request = " ".join(task).strip()
    output = Console()
    progress = Console(stderr=True)
    try:
        settings = Settings.from_env(
            base_url=base_url,
            model=model,
            max_steps=max_steps,
            tool_top_k=top_k,
            card_top_k=top_k,
            stream=False if no_stream else None,
            allow_remote_model=True if allow_remote_model else None,
            verbose=True if verbose else None,
            debug=True if debug else None,
        )
        registry = build_default_registry(settings.max_observation_chars)
        with LocalModelClient(settings) as client:
            agent = ReactAgent(
                settings=settings,
                model=client,
                tools=registry,
            )
            status_message = (
                "[cyan]Thinking…[/cyan]"
                if assistant
                else "[cyan]Inspecting Windows…[/cyan]"
            )

            with progress.status(status_message, spinner="dots"):
                result = agent.run(request, assistant_mode=assistant)
    except (TerminusError, ValueError) as exc:
        progress.print(f"[red]Terminus stopped:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(
            json.dumps(
                result.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return

    output.print(Markdown(result.text))
    if verbose or debug:
        output.print()
        table = Table(title="Read trace", show_lines=True)
        table.add_column("Step", justify="right")
        table.add_column("Tool")
        table.add_column("Arguments")
        table.add_column("Observation")
        for entry in result.trace:
            table.add_row(
                str(entry.step),
                entry.tool,
                json.dumps(entry.arguments, ensure_ascii=False),
                entry.observation,
            )
        if result.trace:
            output.print(table)
        output.print(
            "[dim]"
            f"{result.steps} step(s); "
            f"{result.usage.prompt_tokens} prompt + "
            f"{result.usage.completion_tokens} completion tokens"
            "[/dim]"
        )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
