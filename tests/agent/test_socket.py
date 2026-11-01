"""Collector socket security: only the owning app (or the sudo user) may connect, and the socket
lives in a folder only its creator can write. Run: python3 -m unittest discover -s tests/agent"""

import importlib.util
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_spec = importlib.util.spec_from_file_location("agent_sock", os.path.join(ROOT, "agent", "hostwatch_agent.py"))
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class PeerRules(unittest.TestCase):
    def test_launched_by_app_only_that_process(self):
        self.assertTrue(agent.peer_allowed(pid=500, uid=501, owner_pid=500, client_uid=501))
        self.assertFalse(agent.peer_allowed(pid=777, uid=501, owner_pid=500, client_uid=501))   # same user, other process
        self.assertFalse(agent.peer_allowed(pid=500, uid=502, owner_pid=500, client_uid=501))   # pid reused by another user

    def test_started_by_hand_only_that_user(self):
        self.assertTrue(agent.peer_allowed(pid=777, uid=501, owner_pid=0, client_uid=501))
        self.assertFalse(agent.peer_allowed(pid=777, uid=502, owner_pid=0, client_uid=501))


class SocketFile(unittest.TestCase):
    def setUp(self):
        # Unix socket paths are limited to 104 bytes: use a short folder.
        self.base = tempfile.mkdtemp(prefix="hw", dir="/tmp")
        self.path = os.path.join(self.base, "run", "collector.sock")
        agent.STOP.clear()

    def tearDown(self):
        agent.STOP.set()
        time.sleep(0.05)
        agent.STOP.clear()
        shutil.rmtree(self.base, ignore_errors=True)

    def test_permissions(self):
        server = agent.create_server_socket(self.path, os.getuid())
        try:
            sock_mode = stat.S_IMODE(os.lstat(self.path).st_mode)
            folder_mode = stat.S_IMODE(os.lstat(os.path.dirname(self.path)).st_mode)
            self.assertEqual(sock_mode, 0o600)
            self.assertEqual(folder_mode, 0o755)
            self.assertTrue(stat.S_ISSOCK(os.lstat(self.path).st_mode))
        finally:
            server.close()

    def test_replaces_stale_socket_but_never_a_file(self):
        agent.create_server_socket(self.path, os.getuid()).close()        # leaves a stale socket
        agent.create_server_socket(self.path, os.getuid()).close()        # replaced fine
        os.unlink(self.path)
        with open(self.path, "w") as fh:
            fh.write("not a socket")
        with self.assertRaises(RuntimeError):
            agent.create_server_socket(self.path, os.getuid())

    def serve(self, owner_pid):
        server = agent.create_server_socket(self.path, os.getuid())
        t = threading.Thread(target=agent.accept_clients, args=(server, owner_pid, os.getuid()), daemon=True)
        t.start()
        return server

    def connect(self):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(3)
        c.connect(self.path)
        return c

    def test_owner_connects_and_receives_events(self):
        server = self.serve(owner_pid=os.getpid())          # this test process is the "app"
        client = self.connect()
        try:
            for _ in range(50):                             # wait until accepted
                with agent.CLIENTS_LOCK:
                    if agent.CLIENTS:
                        break
                time.sleep(0.02)
            agent.publish({"kind": "exec", "pid": 1, "ppid": 0, "name": "x", "proc": "/x", "target": "/x"})
            self.assertIn(b'"kind":"exec"', client.recv(4096))
        finally:
            client.close()
            server.close()

    def test_other_process_is_cut_off(self):
        server = self.serve(owner_pid=1)                    # owner is launchd: we are not it
        client = self.connect()
        try:
            self.assertEqual(client.recv(4096), b"")       # closed without any data
            with agent.CLIENTS_LOCK:
                self.assertEqual(len(agent.CLIENTS), 0)
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
