#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


BACKEND_DIR = Path(__file__).resolve().parent.parent
MAX_SET_SIZE_EXPONENT = 30


def stop_processes(processes):
    running = [process for process in processes if process.poll() is None]
    for process in running:
        try:
            process.terminate()
        except ProcessLookupError:
            pass

    for process in running:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    for process in running:
        process.wait()


def wait_for_processes(processes):
    pending = set(range(len(processes)))
    while pending:
        for party_id in tuple(pending):
            return_code = processes[party_id].poll()
            if return_code is None:
                continue
            pending.remove(party_id)
            if return_code != 0:
                stop_processes([processes[index] for index in pending])
                return party_id, return_code
        if pending:
            time.sleep(0.05)
    return None


def main():
    parser = argparse.ArgumentParser(description="Run PeHT-MPSI parties for benchmarking.")
    parser.add_argument('--binPath', default='bin/ot_mpsi', help='Binary path, relative to the backend directory')
    parser.add_argument('--numParties', type=int, required=True, help='Number of parties')
    parser.add_argument(
        '--threshold', type=int,
        help='0 for leader-generated balanced per-element thresholds; 2..numParties for a uniform threshold')
    parser.add_argument('--senderSize', type=int, required=True, help='Sender set-size exponent')
    parser.add_argument('--receiverSize', type=int, required=True, help='Receiver set-size exponent')
    parser.add_argument('--numRuns', type=int, default=1, help='Number of benchmark runs')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--traceable', action='store_true', help='Enable traceable mode')
    args = parser.parse_args()

    max_parties = 36 if args.traceable else 38
    if not 4 <= args.numParties <= max_parties:
        parser.error(f'--numParties must be in [4, {max_parties}] for the selected mode')

    threshold = args.threshold if args.threshold is not None else ((args.numParties + 1) // 2)
    if threshold == 1 or threshold < 0 or threshold > args.numParties:
        parser.error('--threshold must be 0 or an integer in [2, numParties]')

    if not 0 <= args.senderSize <= MAX_SET_SIZE_EXPONENT:
        parser.error(f'--senderSize must be in [0, {MAX_SET_SIZE_EXPONENT}]')
    if not 0 <= args.receiverSize <= MAX_SET_SIZE_EXPONENT:
        parser.error(f'--receiverSize must be in [0, {MAX_SET_SIZE_EXPONENT}]')
    if args.receiverSize < args.senderSize:
        parser.error('--receiverSize must be at least --senderSize')
    if args.numRuns <= 0:
        parser.error('--numRuns must be positive')

    binary_path = Path(args.binPath).expanduser()
    if not binary_path.is_absolute():
        binary_path = BACKEND_DIR / binary_path
    binary_path = binary_path.resolve()
    if not binary_path.is_file() or not os.access(binary_path, os.X_OK):
        parser.error(f'benchmark binary is missing or not executable: {binary_path}')

    keys_dir = BACKEND_DIR / "keys"
    if keys_dir.is_symlink() or (keys_dir.exists() and not keys_dir.is_dir()):
        parser.error(f'refusing to replace unsafe keys path: {keys_dir}')
    if keys_dir.exists():
        try:
            shutil.rmtree(keys_dir)
        except OSError as error:
            parser.exit(1, f'failed to remove {keys_dir}: {error}\n')

    sender_size = 1 << args.senderSize
    receiver_size = 1 << args.receiverSize
    processes = []

    try:
        for party_id in range(args.numParties):
            shared_size = ((party_id + 1) * sender_size) // args.numParties
            command = [
                str(binary_path),
                "-partyID", str(party_id),
                "-numParties", str(args.numParties),
                "-threshold", str(threshold),
                "-senderSize", str(sender_size),
                "-receiverSize", str(receiver_size),
                "-sharedSize", str(shared_size),
                "-numRuns", str(args.numRuns),
            ]
            if args.traceable:
                command.append("-traceable")
            if args.debug:
                command.append("-debug")
            processes.append(subprocess.Popen(command, cwd=BACKEND_DIR))

        failure = wait_for_processes(processes)
    except KeyboardInterrupt:
        stop_processes(processes)
        print("Interrupted; all party processes were stopped.", file=sys.stderr)
        return 130
    except OSError as error:
        stop_processes(processes)
        parser.exit(1, f'failed to start benchmark: {error}\n')

    if failure is not None:
        party_id, return_code = failure
        print(f"Party {party_id} exited with status {return_code}; remaining parties were stopped.", file=sys.stderr)
        return 1

    print("All parties have finished running.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
