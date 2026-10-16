# Third-party licenses

KROT application code is licensed under GPL-3.0-only. Its dependencies and
embedded fonts retain their original licenses and copyright notices.

Release archives include `THIRD_PARTY_NOTICES.txt`, generated from the locked
runtime dependencies for that platform. To regenerate it after fetching and
building the dependencies:

```sh
python scripts/collect_licenses.py --target x86_64-unknown-linux-gnu --output target/THIRD_PARTY_NOTICES.txt
```

For Windows releases, use `--target x86_64-pc-windows-msvc`. The collector uses
Cargo's locked metadata and dependency tree. Metadata may download missing
locked sources; the collector does not update dependency versions. It excludes
build and development dependencies, preserves packaged license and attribution
files, and fails when a dependency has no usable license text. Standard license
texts for reviewed crate versions whose published archives omit them are in
`licenses/standard`.

The default egui fonts are Hack, Noto Emoji, Ubuntu Light, and emoji-icon-font.
Their original license texts and copyright notices are in `licenses/fonts`.
These fonts remain under their respective licenses; GPL-3.0-only does not
replace their licensing terms.
