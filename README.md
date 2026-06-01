# trexnegro.github.io

Personal site for **SixSixSix** — offensive security research.

Live: <https://trexnegro.github.io>

## Stack

- Jekyll + [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy) theme
- GitHub Pages (free)
- Browser-native translation for non-English readers (no i18n pipeline)

## Local development

```bash
# one-time
gem install --user-install bundler
export PATH="$HOME/.local/share/gem/ruby/3.3.0/bin:$PATH"

# every time
bin/serve-local
# → http://127.0.0.1:4000
```

## Writing

```bash
# new research paper (longform: TL;DR / hypothesis / method / results)
bin/new-research softirq-context-lpe-limits

# new short writeup
bin/new-writeup ctf-htb-foo
```

Edit the resulting `_posts/<date>-<slug>.md`, save, preview at `http://127.0.0.1:4000`.

## Publishing

Push to `master`. GitHub Pages rebuilds in ~30s.

```bash
git add _posts/<file>
git commit -m "research: <slug>"
git push origin master
```

## Conventions

- Posts are **English-primary**. Spanish-original content uses `lang: es` in frontmatter.
- Categories: `Research` (papers), `Writeup` (short), `Tools` (releases).
- Tags: lowercase, kebab-case, technology-first (`kernel`, `edr`, `oauth`, …).
- Math: `math: true` in frontmatter enables MathJax.
- Diagrams: `mermaid: true` enables Mermaid.
- Code blocks: triple-backtick with language tag for highlighting.

## Backup

Pre-Chirpy state (Minimal Mistakes theme) is preserved in branch `mm-backup`.
