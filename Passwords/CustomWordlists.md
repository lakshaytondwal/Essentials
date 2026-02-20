# Custom Wordlists

## 1. Crunch

Generates wordlists from a character set.

```bash
crunch <min-len> <max-len> -o wordlist1.txt
```

* `-t @,%^`
  * Specifies a pattern, eg: @@god@@@@ where the only the @'s, ,'s, %'s, and ^'s will change.
  * `@` will insert lower case characters
  * `,` will insert upper case characters
  * `%` will insert numbers
  * `^` will insert symbols

---

## 2. cupp

Generates dictionaries for attacks from personal data

```bash
cupp -i
```

---

## 3. CeWL

CeWL extracts relevant words from a target website.

```bash
cewl -d 1 -m 4 https://example.org -w wordlist3.txt
```

* `-d <x>` or `--depth <x>` = Depth to spider to, default 2.
* `-m` or `--min_word_length` = Minimum word length, default 3.
* `-w` or `--write` = Write the output to the file.

```bash
cewl -e -n https://example.org -w wordlist4.txt
```

* `-n` or `--no-words` = Don't output the wordlist.
* `e` or `--email` = Include email addresses.

---
