# writeups

Source for <https://khanh1916.github.io/writeups/>, where I publish my security
walkthroughs: CTF machines, labs I built myself, and the notes that go with them.

Built with Jekyll on GitHub Pages. No theme gem, no plugins: the layouts in
`_layouts/`, the partials in `_includes/` and the single stylesheet in
`assets/css/main.css` are all there is.

```
_layouts/     default, home, post
_includes/    head, header, footer
assets/css/   main.css       one stylesheet, light and dark
assets/js/    site.js        progressive extras, nothing needed to read a post
_posts/       the write-ups, bilingual (EN / VI)
images/       screenshots, one folder per write-up
```

Every post carries its own metadata in the front matter, and the layout turns it
into the fact bar at the top of the page:

```yaml
platform: VulnHub      # where the target comes from
difficulty: Beginner
flags: 3               # flags_label renames it, e.g. "Findings"
read: 12               # minutes, counted on the English half
bilingual: true        # shows the EN / VI switch
tags: [vulnhub, pentest]
```

Everything here runs against my own lab or a public training target. Never point
these techniques at a system you do not own or have permission to test.

Written by Nguyen Nam Khanh ([@Khanh1916](https://github.com/Khanh1916)).
