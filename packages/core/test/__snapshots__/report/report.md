## depward: 5 findings (1 critical, 1 high, 1 medium, 2 info)

| Risk | Package | Finding | Why |
|---|---|---|---|
| 🔴 critical | <code>evil-pkg@&#8203;1.0.1</code> | <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#env-exfil-pattern"><code>env-exfil-pattern</code></a> | reads sensitive environment variables and uses the network in the same file |
| 🟠 high | <code>evil-pkg@&#8203;1.0.1</code> | <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#fs-sensitive-path"><code>fs-sensitive-path</code></a> | references \\x1b\[2Kcredential\\x1b\[31m locations |
| 🟡 medium | <code>@&#8203;scope/native@&#8203;2.0.0</code> | <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#install-script"><code>install-script</code></a> | runs install scripts (install) |
| ⚪ info | <code>evil-pkg@&#8203;1.0.1</code> | <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#hardcoded-endpoint"><code>hardcoded-endpoint</code></a> | contains hardcoded network endpoints |
| ⚪ info | <code>plain</code> | <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#minified-only"><code>minified-only</code></a> | ships only minified code |

<details open><summary>🔴 <code>evil-pkg@&#8203;1.0.1</code>: 3 findings</summary>

- **critical** <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#env-exfil-pattern"><code>env-exfil-pattern</code></a>: reads sensitive environment variables and uses the network in the same file
  - <code>index.js\:2</code> enumerates process.env (JSON.stringify(process.env))
  - <code>index.js\:3</code> network\: fetch
- **high** <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#fs-sensitive-path"><code>fs-sensitive-path</code></a>: references \\x1b\[2Kcredential\\x1b\[31m locations
  - <code>lib/\\u202etxt.js\:7</code> <code>\~/.ssh/id\_rsa \| &#60;script&#62;alert(1)&#60;/script&#62; \`x\` @&#8203;octocat \[a\](https\://x.example.invalid)</code> SSH keys\\x0asecond line
- **info** <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#hardcoded-endpoint"><code>hardcoded-endpoint</code></a>: contains hardcoded network endpoints
  - <code>index.js\:3</code> <code>https\://collect.example.invalid/e</code>

</details>

<details><summary>🟡 <code>@&#8203;scope/native@&#8203;2.0.0</code>: 1 finding</summary>

- **medium** <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#install-script"><code>install-script</code></a>: runs install scripts (install)
  - <code>package.json</code> <code>node-gyp rebuild</code> install

</details>

<details><summary>⚪ <code>plain</code>: 1 finding</summary>

- **info** <a href="https://github.com/lavitsamson/depward/blob/main/docs/findings.md#minified-only"><code>minified-only</code></a>: ships only minified code
  - 2 JS file(s), all minified

</details>
