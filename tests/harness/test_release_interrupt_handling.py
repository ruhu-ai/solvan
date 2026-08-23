"""A killed release must stay resumable.

The release runner checkpoints nineteen phases so an interrupted deployment
can continue rather than restart. That contract held only for SIGINT: the
handler that writes ``INTERRUPTED`` was an ``except KeyboardInterrupt``, and
neither SIGHUP nor SIGTERM raises one. A closed terminal therefore left the
receipt at ``IN_PROGRESS``, which `_resume_release_receipt` refuses, so the
deployment could not be resumed and its ID could not be reused -- stranding
every completed phase, including an accepted managed build.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap


def _signal_exits_through_keyboard_interrupt(name: str) -> str:
    """Run the real installer, raise the signal, report what was caught."""

    program = textwrap.dedent(
        f"""
        import os, signal, sys
        sys.path.insert(0, {os.getcwd()!r})
        from tools.deploy_release import _install_interrupt_handlers

        _install_interrupt_handlers()
        try:
            os.kill(os.getpid(), signal.{name})
        except KeyboardInterrupt:
            print("KEYBOARD_INTERRUPT")
        else:
            print("NOT_RAISED")
        """
    )
    return subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=30
    ).stdout.strip()


def test_a_hang_up_reaches_the_durable_checkpoint_path() -> None:
    """SIGHUP is what a closed terminal sends, and what stranded staging-01."""

    assert _signal_exits_through_keyboard_interrupt("SIGHUP") == "KEYBOARD_INTERRUPT"


def test_a_termination_request_reaches_the_durable_checkpoint_path() -> None:
    assert _signal_exits_through_keyboard_interrupt("SIGTERM") == "KEYBOARD_INTERRUPT"


def test_both_signals_are_actually_installed_rather_than_left_default() -> None:
    """A handler that is registered but still SIG_DFL would prove nothing."""

    from tools.deploy_release import _install_interrupt_handlers

    previous = {s: signal.getsignal(s) for s in (signal.SIGHUP, signal.SIGTERM)}
    try:
        _install_interrupt_handlers()
        for received in (signal.SIGHUP, signal.SIGTERM):
            installed = signal.getsignal(received)
            assert callable(installed), f"{received!r} kept a non-callable disposition"
            assert installed not in (signal.SIG_DFL, signal.SIG_IGN)
    finally:
        for received, handler in previous.items():
            signal.signal(received, handler)


def test_sigint_is_left_alone_because_python_already_raises_it() -> None:
    """Rebinding SIGINT would replace a working path with a second one."""

    from tools.deploy_release import _install_interrupt_handlers

    before = signal.getsignal(signal.SIGINT)
    previous = {s: signal.getsignal(s) for s in (signal.SIGHUP, signal.SIGTERM)}
    try:
        _install_interrupt_handlers()
        assert signal.getsignal(signal.SIGINT) is before
    finally:
        for received, handler in previous.items():
            signal.signal(received, handler)
