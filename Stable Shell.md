# Reverse-Shell-TTY-Cheat-Sheet

Simple TTY cheat sheet for shell stabilization
Prevents you from killing your reverse shells and adds proper shell functionality

Python

- python -c 'import pty; pty.spawn("/bin/bash")'

Script

- /usr/bin/script -qc /bin/bash /dev/null

Perl

- perl -e 'exec "/bin/sh";'
- perl: exec "/bin/sh";

Linux OS

- echo os.system('/bin/bash')
- /bin/sh -i

Ruby

- ruby: exec "/bin/sh"

Lua

- lua: os.execute('/bin/sh')

## TTY Shell Stabilization Process

Victim

```bash
python -c 'import pty; pty.spawn("/bin/bash")' OR /usr/bin/script -qc /bin/bash /dev/null
Control + Z
```

Attacker

```bash
stty raw -echo
fg
ENTER
ENTER
```

Victim

```bash
export TERM=xterm
stty cols 132 rows 34
```
