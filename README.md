# notes

Source for <https://khanh1916.github.io/writeups/>, my personal blog about
technology: projects, labs and notes on how things work. Security walkthroughs
(CTF machines, labs I built myself) are one part of it.

Built with Jekyll on GitHub Pages. No theme gem, no plugins: the layouts in
`_layouts/`, the partials in `_includes/` and the single stylesheet in
`assets/css/main.css` are all there is.

```
_layouts/     default, home, post
_includes/    head, header, footer
assets/css/   main.css       one stylesheet, light and dark
assets/js/    site.js        progressive extras, nothing needed to read a post
_posts/       the posts, some bilingual (EN / VI)
images/       screenshots, one folder per post
```

Every post carries its own metadata in the front matter, and the layout turns it
into the fact bar at the top of the page. All of it is optional: a cell is left
out when its field is missing, so a non-security post can drop the lab fields.

```yaml
platform: VulnHub      # where the target comes from
difficulty: Beginner
flags: 3               # flags_label renames it, e.g. "Findings"
read: 12               # minutes, counted on the English half
bilingual: true        # shows the EN / VI switch
tags: [vulnhub, pentest]
```

Security posts only target my own lab or a public training machine. Never point
those techniques at a system you do not own or have permission to test.

Written by Nguyen Nam Khanh ([@Khanh1916](https://github.com/Khanh1916)).
