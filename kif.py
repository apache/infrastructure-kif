#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
KIF: Kill It with Fire (or a depressed space alien)
"""

# Initial module imports
import os
import sys
import psutil
import yaml
import re
import subprocess
import argparse
import socket
import time
import asfpy.syslog
import asfpy.messaging

# Redirect stdout to syslog+stdout
print = asfpy.syslog.Printer(stdout=True)


# define binary metrics
KB = (2 ** 10)
MB = (2 ** 20)
GB = (2 ** 30)
TB = (2 ** 40)

# Helper func
def who_am_i():
    """Returns the FQDN of the box the program runs on"""
    try:
        # Get local hostname (what you see in the terminal)
        local_hostname = socket.gethostname()
        # Get all address info segments for the local host
        canonical_names = [
            address[3] for address in
            socket.getaddrinfo(local_hostname, None, 0, socket.SOCK_DGRAM, 0, socket.AI_CANONNAME)
            if address[3]
        ]
        # For each canonical name, see if we find $local_hostname.something.tld, and if so, return that.
        if canonical_names:
            prefix = f"{local_hostname}."
            for name in canonical_names:
                if name.startswith(prefix):
                    return name
            # No match, just return the first occurrence.
            return canonical_names[0]
    except socket.error:
        pass
    # Fall back to socket.getfqdn
    return socket.getfqdn()

# hostname, pid file etc
ME = who_am_i()
TEMPLATE_EMAIL = open("email_template.txt", "r").read()
# Default to checking triggers every N seconds.
DEFAULT_INTERVAL = 300


class ProcessInfo(object):
    def __init__(self, pid=None):
        if pid is None:
            # This instance will aggregate values across multiple processes,
            # so we'll zero the numerics.
            self.mem = 0
            self.mempct = 0
            self.fds = 0
            self.age = 0
            self.state = ''  # can't aggregate state, but needs a value
            self.conns = 0
            self.conns_local = 0
            self.command = '(root)'
            return

        proc = psutil.Process(pid)

        self.mem = proc.memory_info().rss
        self.mempct = proc.memory_percent()
        self.fds = proc.num_fds()
        self.age = time.time() - proc.create_time()
        self.state = proc.status()
        self.command = " ".join(proc.cmdline())

        self.conns = len(proc.connections())
        self.conns_local = 0
        for connection in proc.connections():
            if connection.raddr and connection.raddr[0]:
                if RE_LOCAL_IP.match(connection.raddr[0]) \
                        or connection.raddr[0] == '::1':
                    self.conns_local += 1

    def accumulate(self, other):
        self.mem += other.mem
        self.mempct += other.mempct  ### this is likely wrong
        self.fds += other.fds
        self.conns += other.conns
        self.conns_local += other.conns_local
        self.age += other.age
        # cannot accumulate .state


RE_LOCAL_IP = re.compile(r'^(10|192|127)\.')


def getuser(pid):
    try:
        proc = psutil.Process(pid)
        return proc.username()
    except (psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
        print("Could not access process, it might have gone away...")
        return None


# getprocs: Get all processes and their command line stack
def getprocs():
    procs = {}
    for p in psutil.process_iter():
        try:
            pinfo = p.as_dict(attrs=['pid', 'name', 'username', 'status', 'cmdline'])
            content = pinfo['cmdline']
            if not content:
                content = pinfo['name']  # Fall back if no cmdline present
            pid = pinfo['pid']
            if len(content) > 0 and len(content[0]) > 0:
                content = [c for c in content if len(c) > 0]
                procs[pid] = content
        except (psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
            print("Could not access process, it might have gone away...")
            continue
    return procs


def checkTriggers(id, info, triggers, dead=False):
    # if len(triggers) > 0:
        # print("  - Checking triggers:")
    for trigger, value in triggers.items():
        # print("    - Checking against trigger %s" % trigger)

        # maxmemory: Process can max use N amount of memory or it triggers
        if trigger == 'maxmemory':
            if isinstance(value, str):
                value = value.lower()
                if value.find("%") != -1:  # percentage check
                    maxmem = float(value.replace('%', ''))
                    cmem = info.mempct
                    cvar = '%'
                elif value.find('kb') != -1:  # kb check
                    maxmem = int(value.replace('kb', '')) * KB
                    cmem = info.mem
                    cvar = ' bytes'
                elif value.find('mb') != -1:  # mb check
                    maxmem = int(value.replace('mb', '')) * MB
                    cmem = info.mem
                    cvar = ' bytes'
                elif value.find('gb') != -1:  # gb check
                    maxmem = int(value.replace('gb', '')) * GB
                    cmem = info.mem
                    cvar = ' bytes'
                elif value.find('tb') != -1:  # tb check
                    maxmem = int(value.replace('tb', '')) * TB
                    cmem = info.mem
                    cvar = ' bytes'
            elif isinstance(value, int):
                maxmem = value
                cmem = info.mem
                cvar = ' bytes'
            lstr = "      - %s: '%s' is using %u%s memory, max allowed is %u%s" % (
            id, info.command, cmem + 0.5, cvar, maxmem + 0.5, cvar)
            print(lstr)
            if cmem > maxmem:
                print("    - Trigger fired!")
                return lstr

        # maxfds: maximum number of file descriptors
        if trigger == 'maxfds':
            maxfds = int(value)
            cfds = info.fds
            lstr = "      - %s: '%s' is using %u FDs, max allowed is %u" % (id, info.command, cfds, value)
            print(lstr)
            if cfds > maxfds:
                print("    - Trigger fired!")
                return lstr

        # maxconns: maximum number of open connections
        if trigger == 'maxconns':
            maxconns = int(value)
            ccons = info.conns
            lstr = "      - %s: '%s' is using %u connections, max allowed is %u" % (id, info.command, ccons, value)
            print(lstr)
            if ccons > maxconns:
                print("    - Trigger fired!")
                return lstr

        # maxlocalconns: maximum number of open connections in local network
        if trigger == 'maxlocalconns':
            maxconns = int(value)
            ccons = info.conns_local
            lstr = "      - %s: '%s' is using %u LAN connections, max allowed is %u" % (id, info.command, ccons, value)
            print(lstr)
            if ccons > maxconns:
                print("    - Trigger fired!")
                return lstr

        # maxage: maximum age of a process (NOT cpu time)
        if trigger == 'maxage':
            if value.find('s') != -1:  # seconds
                maxage = int(value.replace('s', ''))
                cage = info.age
                cvar = ' seconds'
            elif value.find('m') != -1:  # minutes
                maxage = int(value.replace('m', '')) * 60
                cage = info.age
                cvar = ' minutes'
            elif value.find('h') != -1:  # hours
                maxage = int(value.replace('h', '')) * 3600
                cage = info.age
                cvar = ' hours'
            elif value.find('d') != -1:  # days
                maxage = int(value.replace('d', '')) * 86400
                cage = info.age
                cvar = ' days'
            else:
                maxage = int(value)
                cage = info.age
            lstr = "      - %s: '%s' is %u seconds old, max allowed is %u" % (id, info.command, cage, maxage)
            print(lstr)
            if cage > maxage:
                print("    - Trigger fired!")
                return lstr

        # state: kill processes in a specific state (zombie etc)
        if trigger == 'state':
            cstate = info.state
            lstr = "      - %s: '%s' is in state '%s'" % (id, info.command, cstate)
            print(lstr)
            if cstate == value:
                print("    - Trigger fired!")
                return lstr
    return None


def scan_for_triggers(config):
    procs = getprocs()  # get all current processes
    actions = []

    # For each rule..
    for id, rule in config['rules'].items():
        # print("- Running rule %s" % id)
        # Is this process running here?
        pids = []
        if 'host_must_match' in rule:
            if not re.match(rule['host_must_match'], ME):
                # print(f"Ignoring rule-set '{id}', hostname '{ME}' does not match host_must_match criterion.")
                continue
        if 'host_must_not_match' in rule:
            if re.match(rule['host_must_not_match'], ME):
                # print(f"Ignoring rule-set '{id}', hostname '{ME}' matches host_must_not_match criterion.")
                continue
        if 'procid' in rule:
            procid = rule['procid']
            # print("  - Checking for process %s" % procid)
            for xpid, cmdline in procs.items():
                cmdstring = " ".join(cmdline)
                addit = False
                if isinstance(procid, str):
                    if cmdstring.find(rule['procid']) != -1:
                        addit = True
                elif isinstance(procid, list):
                    if cmdline == procid:
                        addit = True
                # If uid is specified and doesn't match here, discard match.
                if 'uid' in rule:
                    xuid = getuser(xpid)
                    if xuid != rule['uid']:
                        addit = False
                if addit:
                    if not ('ignore' in rule):
                        addit = True
                    elif isinstance(rule['ignore'], str) and cmdstring != rule['ignore']:
                        addit = True
                    elif isinstance(rule['ignore'], list) and cmdline != rule['ignore']:
                        addit = True
                    if 'ignorepidfile' in rule:
                        try:
                            ppid = int(open(rule['ignorepidfile']).read())
                            if ppid == xpid:
                                # print("Ignoring %u, matches pid file %s!" % (ppid, rule['ignorepidfile']))
                                addit = False
                        except Exception as err:
                            print(err)
                    if 'ignorematch' in rule:
                        ignm = rule['ignorematch']
                        if isinstance(ignm, str) and ignm in cmdstring:
                            # print("Ignoring %u, matches ignorematch directive %s!" % (xpid, rule['ignorematch']))
                            addit = False
                        elif isinstance(ignm, list):
                            for line in ignm:
                                if line in cmdstring:
                                    # print("Ignoring %u, matches ignorematch directive %s!" % (xpid, line))
                                    addit = False
                                    break
                    if addit:
                        pids.append(xpid)
        if 'uid' in rule:
            for xpid, cmdline in procs.items():
                cmdstring = " ".join(cmdline)
                uid = getuser(xpid)
                if uid == rule['uid']:
                    addit = False
                    if not ('ignore' in rule):
                        addit = True
                    elif isinstance(rule['ignore'], str) and cmdstring != rule['ignore']:
                        addit = True
                    elif isinstance(rule['ignore'], list) and cmdline != rule['ignore']:
                        addit = True
                    if 'ignorepidfile' in rule:
                        try:
                            ppid = int(open(rule['ignorepidfile']).read())
                            if ppid == xpid:
                                # print("Ignoring %u, matches pid file %s!" % (ppid, rule['ignorepidfile']))
                                addit = False
                        except Exception as err:
                            print(err)
                    if 'ignorematch' in rule:
                        ignm = rule['ignorematch']
                        if isinstance(ignm, str) and ignm in cmdstring:
                            # print("Ignoring %u, matches ignorematch directive %s!" % (xpid, rule['ignorematch']))
                            addit = False
                        elif isinstance(ignm, list):
                            for line in ignm:
                                if line in cmdstring:
                                    # print("Ignoring %u, matches ignorematch directive %s!" % (xpid, line))
                                    addit = False
                                    break
                    if addit:
                        pids.append(xpid)

        # If proc is running, analyze it
        analysis = ProcessInfo()  # no pid. accumulator.
        for pid in pids:
            # print("  - Found process at PID %u" % pid)

            try:
                # Get all relevant data from this PID
                info = ProcessInfo(pid)

                # If combining, combine into the analysis hash
                if 'combine' in rule and rule['combine'] == True:
                    analysis.accumulate(info)
                else:
                    # If running a per-pid test, run it:
                    err = checkTriggers(id, info, rule['triggers'])
                    if err:
                        action = {
                            'pids': [],
                            'trigger': "",
                            'runlist': [],
                            'notify': rule.get('notify', None),
                            'kills': {}
                        }
                        if 'runlist' in rule and len(rule['runlist']) > 0:
                            action['runlist'] = rule['runlist']
                        if 'kill' in rule and rule['kill'] == True:
                            sig = 9
                            if 'killwith' in rule:
                                sig = int(rule['killwith'])
                            action['kills'][pid] = sig
                        action['trigger'] = err
                        actions.append(action)
            except:
                print("Could not analyze proc %u, bailing!" % pid)
                continue
        if len(pids) > 0:
            # If combined trigger test, run it now
            if 'combine' in rule and rule['combine'] == True:
                err = checkTriggers(id, analysis, rule['triggers'])
                if err:
                    action = {
                        'pids': [],
                        'trigger': "",
                        'runlist': [],
                        'notify': rule.get('notify', None),
                        'kills': {}
                    }
                    if 'runlist' in rule and len(rule['runlist']) > 0:
                        action['runlist'] = rule['runlist']
                    if 'kill' in rule and rule['kill'] == True:
                        sig = 9
                        if 'killwith' in rule:
                            sig = int(rule['killwith'])
                        for ypid in pids:
                            action['kills'][ypid] = sig
                    action['trigger'] = err
                    actions.append(action)
        else:
            pass
            # print("  - No matching processes found")

    return actions


def run_actions(config, actions, debug=False):
    goods = 0
    bads = 0
    triggered_total = 0
    email_triggers = ""
    email_actions = ""

    for action in actions:
        triggered_total += 1
        print("Following triggers were detected:")
        print("- %s" % action['trigger'])
        if action.get('notify', 'email') in [None, 'email']:
            email_triggers += "- %s\n" % action['trigger']
        print("Running triggered commands:")
        rloutput = ""
        for item in action['runlist']:
            print("- %s" % item)
            rloutput += "- %s" % item
            if action.get('notify', 'email') in [None, 'email']:
                email_actions += "- %s" % item
            try:
                if not debug:
                    subprocess.check_output(item, shell=True, stderr=subprocess.STDOUT)
                    rloutput += " (success)"
                    if action.get('notify', 'email') in [None, 'email']:
                        email_actions += " (success)"
                else:
                    print("(disabled due to --debug flag)")
                    rloutput += " (disabled due to --debug)"
                    if action.get('notify', 'email') in [None, 'email']:
                        email_actions += " (disabled due to --debug)"
                goods += 1
            except subprocess.CalledProcessError as e:
                print("command failed: %s" % e.output)
                rloutput += " (failed!: %s)" % e.output
                if action.get('notify', 'email') in [None, 'email']:
                    email_actions += " (failed!: %s)" % e.output
                bads += 1
            rloutput += "\n"
            if action.get('notify', 'email') in [None, 'email']:
                email_actions += "\n"
        for pid, sig in action['kills'].items():
            print("- KILL PID %u with sig %u" % (pid, sig))
            rloutput += "- KILL PID %u with sig %u" % (pid, sig)
            if action.get('notify', 'email') in [None, 'email']:
                email_actions += "- KILL PID %u with sig %u" % (pid, sig)
            if not debug:
                try:
                    os.kill(pid, sig)
                except OSError:
                    email_actions += "(failed, no such process!)"
            else:
                print(" (disabled due to --debug flag)")
                rloutput += " (disabled due to --debug flag)"
                if action.get('notify', 'email') in [None, 'email']:
                    email_actions += " (disabled due to --debug flag)"
            rloutput += "\n"
            if action.get('notify', 'email') in [None, 'email']:
                email_actions += "\n"
            goods += 1
        print("%u calls succeeded, %u failed." % (goods, bads))

    if email_actions and 'notifications' in config and 'email' in config['notifications']:
        ecfg = config['notifications']['email']
        if 'rcpt' in ecfg and 'from' in ecfg and not debug:
            subject = "[KIF] events triggered on %s" % ME
            msg = TEMPLATE_EMAIL.format(ME=who_am_i(), triggers=email_triggers, actions=email_actions)
            asfpy.messaging.mail(sender=ecfg['from'], recipient=ecfg['rcpt'], subject=subject, message=msg)


# Get started!
def main():
    # Get args, if any
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Debug run (don't execute runlists)", action='store_true')
    parser.add_argument("-c", "--config", help="Path to the config file if not in ./kif.yaml")
    args = parser.parse_args()

    if not args.config:
        config = yaml.safe_load(open("kif.yaml"))
    else:
        config = yaml.safe_load(open(args.config))

    if os.getuid() != 0:
        print("Kif must be run as root!")
        sys.exit(-1)

    interval = int(config.get('daemon', {})
                   .get('interval', DEFAULT_INTERVAL))

    # Loop forever and ever
    while True:
        if 'rules' not in config:
            print('- NO RULES TO CHECK')
        else:
            # Now actually run things
            actions = scan_for_triggers(config)
            if actions:
                run_actions(config, actions, args.debug)
        # print(f'KIF run finished, waiting {interval} seconds till next run.')
        time.sleep(interval)


if __name__ == '__main__':
    main()

    
