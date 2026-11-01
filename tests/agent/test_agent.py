"""Collector parser tests. Fixtures are real lines captured on this Mac (tcpdump -vv with pktap
metadata, nettop -P) during development. Run: python3 -m unittest discover -s tests/agent"""

import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_spec = importlib.util.spec_from_file_location("agent", os.path.join(ROOT, "agent", "hostwatch_agent.py"))
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class DNSAnswers(unittest.TestCase):
    """tcpdump -vv output: the question name is kept even behind CNAMEs."""

    def test_a_records(self):
        line = ("    192.168.1.1.53 > 192.168.1.5.61234: [udp sum ok] 4660 q: A? www.google.com. 2/0/0 "
                "www.google.com. A 142.250.154.100, www.google.com. A 142.250.154.101 (92)")
        self.assertEqual(agent.parse_dns_line(line), ("www.google.com", ["142.250.154.100", "142.250.154.101"]))

    def test_cname_keeps_question(self):
        line = ("    192.168.1.1.53 > 192.168.1.5.61234: [no cksum] 8738 q: A? api.github.com. 2/0/0 "
                "api.github.com. CNAME lb.github.com., lb.github.com. A 140.82.121.6 (102)")
        self.assertEqual(agent.parse_dns_line(line), ("api.github.com", ["140.82.121.6"]))

    def test_aaaa(self):
        line = ("    192.168.1.1.53 > 192.168.1.5.61234: [no cksum] 13107 q: AAAA? www.google.com. 1/0/0 "
                "www.google.com. AAAA 2a00:1450:4001:82a::2004 (74)")
        self.assertEqual(agent.parse_dns_line(line), ("www.google.com", ["2a00:1450:4001:82a::2004"]))

    def test_non_dns_line(self):
        self.assertEqual(agent.parse_dns_line("05:23:10.048273 (in) IP (tos 0x0, ttl 64)"), (None, []))


class ConnectionPackets(unittest.TestCase):
    """pktap SYNs: outgoing ones carry the process; incoming '(in)' ones must not be attributed."""

    def meta(self, header):
        m = agent._META.search(header)
        return m.group(1) if m else ""

    def test_chrome_outgoing_syn(self):
        header = ("05:26:08.309646 (proc Google Chrome He:10131, out) IP (tos 0x0, ttl 64, id 0, offset 0, "
                  "flags [DF], proto TCP (6), length 48)")
        line = ("192.168.1.5.62881 > 198.51.100.7.443: Flags [S], cksum 0x4dd3 (correct), seq 3763702289, "
                "win 65535, options [mss 1460,sackOK,eol], length 0")
        self.assertEqual(agent.parse_syn(line, self.meta(header)), (10131, "Google Chrome He", "198.51.100.7:443", True))

    def test_process_name_with_digits(self):
        header = ("05:27:56.666477 (proc python3.12:44449, out) IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], "
                  "proto TCP (6), length 64, bad cksum 0 (->3cb6)!)")
        line = "127.0.0.1.63355 > 127.0.0.1.60328: Flags [S], cksum 0xfe34 (incorrect -> 0x5aff), seq 1, length 0"
        self.assertEqual(agent.parse_syn(line, self.meta(header)), (44449, "python3.12", "127.0.0.1:60328", True))

    def test_incoming_not_attributed(self):
        header = ("05:23:10.048273 (in) IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), "
                  "length 64, bad cksum 0 (->3cb6)!)")
        line = "127.0.0.1.63280 > 127.0.0.1.47831: Flags [S], cksum 0xfe34 (incorrect -> 0x427a), seq 1, length 0"
        self.assertIsNone(agent.parse_syn(line, self.meta(header)))

    def test_syn_ack_ignored(self):
        line = "142.250.154.100.80 > 192.168.1.5.61235: Flags [S.], seq 9, ack 2, win 65535, length 0"
        self.assertIsNone(agent.parse_syn(line, "proc curl:28169, svc BE, in"))

    def test_ipv6_with_pid_metadata(self):
        line = ("05:20:31.000000 (en0, pid 30001 e_pid 30001, out) IP6 (hlim 64, next-header TCP (6) payload "
                "length: 44) 2a02:1::5.50000 > 2a00:1450:4001:82a::2004.443: Flags [S], seq 1, length 0")
        self.assertEqual(agent.parse_syn(line, self.meta(line)),
                         (30001, "", "[2a00:1450:4001:82a::2004]:443", True))


class NettopLines(unittest.TestCase):
    def test_process_line(self):
        self.assertEqual(agent.parse_nettop_line("05:28:30.557179,curl.44636,,,10053,343,0,0,0,,,,,,,,,,,,\n"),
                         ("curl", 44636, 10053, 343))

    def test_name_with_dots(self):
        self.assertEqual(agent.parse_nettop_line("05:28:30.5,com.apple.WebKit.Networking.812,,,10,20,0,0,0,,\n"),
                         ("com.apple.WebKit.Networking", 812, 10, 20))

    def test_header_and_flow_lines_skipped(self):
        self.assertIsNone(agent.parse_nettop_line("time,,interface,state,bytes_in,bytes_out,rx_dupe,\n"))
        self.assertIsNone(agent.parse_nettop_line(
            "05:27:42.8,tcp4 192.168.1.5:51423<->17.242.218.132:5223,en0,Established,1601676,6255400,\n"))


class InferredDestination(unittest.TestCase):
    """Short connections nobody saw: destination from the command line + recent DNS answers."""

    @classmethod
    def setUpClass(cls):
        agent.remember_dns("google.ua", ["142.251.110.94"])

    def test_bare_host_resolved_by_dns(self):
        self.assertEqual(agent.infer_destination("curl google.ua"), ("142.251.110.94:80", "google.ua", "dns"))

    def test_https_url(self):
        self.assertEqual(agent.infer_destination("curl -s https://google.ua/search?q=1"),
                         ("142.251.110.94:443", "google.ua", "dns"))

    def test_unresolved_name_from_args(self):
        self.assertEqual(agent.infer_destination("curl http://user:pw@api.example.com:8080/x"),
                         ("api.example.com:8080", "api.example.com", "args"))

    def test_port_unknown_for_non_web_tools(self):
        self.assertEqual(agent.infer_destination("nc evil.example 4444"), ("evil.example:?", "evil.example", "args"))

    def test_ip_literal(self):
        self.assertEqual(agent.infer_destination("wget 1.2.3.4"), ("1.2.3.4:80", "", ""))

    def test_files_are_not_hosts(self):
        self.assertEqual(agent.infer_destination("ls /etc/hosts.plist"), ("?:?", "", ""))


class SecretMasking(unittest.TestCase):
    """Command lines go to history: obvious secrets must be masked."""

    def test_authorization_header(self):
        out = agent.format_args(["curl", "-H", "Authorization: Bearer abc.def", "https://h/x?token=zzz&b=1"])
        self.assertEqual(out, "curl -H 'Authorization: Bearer ***' https://h/x?token=***&b=1")

    def test_url_credentials(self):
        self.assertIn("https://user:***@api.example.com", agent.format_args(["curl", "https://user:pa55@api.example.com/x"]))

    def test_token_prefixes(self):
        self.assertEqual(agent.format_args(["git", "push", "https://ghp_ABCDEFGHIJKLMNOP@github.com/x"]),
                         "git push https://ghp_***@github.com/x")

    def test_paths_with_spaces_quoted(self):
        self.assertEqual(agent.format_args(["xattr", "-d", "com.apple.quarantine", "/Users/x/Downloads/Evil App.app"]),
                         "xattr -d com.apple.quarantine '/Users/x/Downloads/Evil App.app'")


class Exclusions(unittest.TestCase):
    def test_hostname_glob(self):
        rules = agent.compile_rules(["net:*.google.com:*"])
        hit = {"kind": "net", "name": "curl", "proc": "/usr/bin/curl", "target": "142.250.154.100:80",
               "host": "www.google.com"}
        miss = dict(hit, target="140.82.121.6:443", host="api.github.com")
        self.assertTrue(agent.is_excluded(rules, hit))
        self.assertFalse(agent.is_excluded(rules, miss))

    def test_address_helpers(self):
        self.assertEqual(agent._strip_host("[2a00:1450:4001:82a::2004]:443"), "2a00:1450:4001:82a::2004")
        self.assertEqual(agent._strip_host("142.250.154.100:80"), "142.250.154.100")
        self.assertEqual(agent._lsof_addr("2a00::1", "443"), "[2a00::1]:443")


if __name__ == "__main__":
    unittest.main()


class TopProcesses(unittest.TestCase):
    def test_cpu_percent_disk_rates_and_new_processes(self):
        sec = 1_000_000_000
        before = {(10, 1): (0, 100, 0, 0), (20, 2): (5 * sec, 900, 1000, 0), (30, 3): (0, 50, 0, 0)}
        after = {(10, 1): (int(2.5 * sec), 100, 0, 5000),    # 2.5 s of CPU in 5 s = 50 %
                 (20, 2): (5 * sec, 900, 6000, 0),             # idle, biggest memory, reads 5000 B
                 (30, 4): (9 * sec, 70, 0, 0)}                 # pid reused (new start): no baseline
        rows, read, write = agent.top_from_snapshots(before, after, 5.0, limit=1)
        self.assertEqual(rows[0][0], 10)
        self.assertAlmostEqual(rows[0][1], 50.0)
        self.assertEqual([r[0] for r in rows], [10, 20])        # top CPU, then top memory not already listed
        self.assertAlmostEqual(read, 1000.0)                   # 5000 B / 5 s
        self.assertAlmostEqual(write, 1000.0)
        self.assertNotIn(30, [r[0] for r in rows])

    def test_only_clients_that_asked_get_top_samples(self):
        client = agent.Client(sock=None)
        ev = {"kind": "top", "procs": []}
        self.assertFalse(client.wants(ev))                    # history recorder, default
        client.configure({"top": True})
        self.assertTrue(client.wants(ev))
        client.configure({"kinds": ["exec"]})                 # kinds don't affect top
        self.assertTrue(client.wants(ev))

    def test_snapshot_reads_real_processes(self):
        if agent._LIBPROC is None:
            self.skipTest("no libproc")
        snap = agent.process_snapshot(agent._LIBPROC, 1.0)
        mine = [v for (pid, _), v in snap.items() if pid == os.getpid()]
        self.assertEqual(len(mine), 1)
        self.assertGreater(mine[0][1], 0)                      # memory footprint


class OwnActivity(unittest.TestCase):
    APP = "/Applications/Hostwatch.app/Contents/MacOS/Hostwatch"

    def setUp(self):
        agent.OWN_EXE = self.APP
        with agent.OUR_TREE_LOCK:
            agent.OUR_TREE.clear()
            agent.OUR_TREE.add(500)                        # the verified owner app

    def tearDown(self):
        agent.OWN_EXE = ""
        with agent.OUR_TREE_LOCK:
            agent.OUR_TREE.clear()

    def exec_event(self, pid, ppid, path, caller_pid=None):
        return {"event": {"exec": {"target": {"audit_token": {"pid": pid}, "ppid": ppid,
                                              "executable": {"path": path}}, "args": [path]}},
                "process": {"audit_token": {"pid": caller_pid or pid}, "ppid": ppid,
                            "executable": {"path": "/bin/sh"}}}

    def open_event(self, pid, path="/tmp/x"):
        return {"event": {"open": {"file": {"path": path}, "fflag": 2}},
                "process": {"audit_token": {"pid": pid}, "ppid": 1, "executable": {"path": "/x"}}}

    def exit_event(self, pid):
        return {"event": {"exit": {"stat": 0}}, "process": {"audit_token": {"pid": pid}, "ppid": 1,
                                                            "executable": {"path": "/x"}}}

    def test_app_and_its_children_are_hidden(self):
        self.assertIsNone(agent.normalize(self.open_event(500, "/tmp/metrics-a")))     # the app's own writes
        self.assertIsNone(agent.normalize(self.exec_event(501, 500, "/usr/bin/codesign")))
        self.assertIsNone(agent.normalize(self.open_event(501, "/tmp/metrics-b")))     # its child too
        self.assertTrue(agent.is_ours_pid(501))

    def test_same_executable_elsewhere_is_hidden_others_are_not(self):
        # Claude Code (pid 700) starts `Hostwatch --mcp`: same executable, so it's ours.
        self.assertIsNone(agent.normalize(self.exec_event(710, 700, self.APP)))
        # A look-alike in another place is reported.
        ev = agent.normalize(self.exec_event(720, 700, "/tmp/Hostwatch.app/Contents/MacOS/Hostwatch"))
        self.assertIsNotNone(ev)
        self.assertIsNotNone(agent.normalize(self.open_event(720, "/tmp/evil")))

    def test_reused_pid_is_reported_again(self):
        self.assertIsNone(agent.normalize(self.exec_event(501, 500, "/usr/bin/codesign")))
        self.assertIsNone(agent.normalize(self.exit_event(501)))                       # exit: never published
        self.assertFalse(agent.is_ours_pid(501))
        self.assertIsNotNone(agent.normalize(self.open_event(501, "/tmp/after-reuse")))
        # Reused by an unrelated exec even without a seen exit.
        agent.normalize(self.exec_event(502, 500, "/usr/bin/true"))
        self.assertIsNotNone(agent.normalize(self.exec_event(502, 1, "/usr/bin/curl")))
        self.assertFalse(agent.is_ours_pid(502))


class NettopBackstop(unittest.TestCase):
    def test_nettop_gets_an_open_pipe_as_stdin(self):
        # With /dev/null as stdin, nettop spins at ~140% CPU polling for key presses.
        seen = {}
        original = agent.subprocess.Popen

        def fake_popen(cmd, **kwargs):
            seen.update(kwargs, cmd=cmd)
            raise OSError("not started in tests")

        agent.subprocess.Popen = fake_popen
        try:
            agent.run_nettop_backstop()
        finally:
            agent.subprocess.Popen = original
        self.assertEqual(seen["cmd"][0], "/usr/bin/nettop")
        self.assertIs(seen.get("stdin"), agent.subprocess.PIPE)
