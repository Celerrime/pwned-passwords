pwned-passwords
---------------

See https://haveibeenpwned.com/Passwords for more info.

```
$ wget https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z  # +9GB
$ 7z x pwned-passwords-ordered-2.0.txt.7z   # +30GB
$ go get github.com/lenartj/pwned-passwords
$ pwned-passwords pwned-passwords-ordered-2.0.txt foo foo2 SUPERpw
foo: FOUND (5061)
foo2: FOUND (6)
SUPERpw: not found
```

100 searches take about 3 seconds using a slow hdd.
