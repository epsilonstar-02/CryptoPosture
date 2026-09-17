---
name: neumorphism-design
description: Design and build websites and web apps using the Neumorphism (Soft UI) style — elements that appear to extrude from or be pressed into the surface, created with dual-shadow technique and matched surface colors. Use this skill whenever the user asks to design, build, create, style, or redesign anything in a Neumorphism or Soft UI style, even if phrased casually like "make it look like soft UI", "neumorphic design", "that raised/embossed button look", "soft shadows", "elements that pop out of the background", or "I want a Neumorphism website/app/component/dashboard". Always use this skill before writing any Neumorphism-related code or design — do NOT attempt it from memory alone.
---

# Neumorphism Design Skill

A complete guide for designing and building Neumorphic / Soft UI interfaces — the style where elements feel physically extruded from or pressed into the surface. Think tactile controls, analog knobs, embossed cards, and precise dual-shadow depth.

---

## The Core Physics (Read First — This Is Everything)

Neumorphism is a simulation of soft plastic or clay material under diffuse light. One rule governs the entire system:

**The element's background color MUST exactly match the page background.**

This is what creates the illusion. When the element is the same color as its parent, the only visual information comes from the shadows — a light shadow cast toward the light source (top-left), and a dark shadow cast away from it (bottom-right). The element appears to be the same material as the page, just shaped differently.

Violating this rule — giving elements white, off-white, or any color that differs from the background — destroys the illusion immediately and reads as "broken Neumorphism."

### The Three Surface States

```css
/* RAISED — element protrudes toward the viewer */
box-shadow:
  -6px -6px 14px var(--shadow-light),
   6px  6px 14px var(--shadow-dark);

/* FLAT — neutral, no depth */
box-shadow:
  -2px -2px 5px var(--shadow-light),
   2px  2px 5px var(--shadow-dark);

/* PRESSED / INSET — element is pushed into the surface */
box-shadow:
  inset -4px -4px 10px var(--shadow-light),
  inset  4px  4px 10px var(--shadow-dark);
```

Interactive elements (buttons, toggles) transition between RAISED (idle) and PRESSED (active).

---

## Step 1: Ask the User These Questions

Ask these in a single message. Tell them to skip anything and you'll apply the defaults.

**1. Mode**
- **Light** *(default)* — Soft gray surface, classic Neumorphism. Warm or cool tone.
- **Dark** — Deep charcoal surface. Same physics, darker atmosphere.
- **Both** — Respects `prefers-color-scheme`.

**2. Surface Color**
The base color everything is built on:
- **Stone Gray** *(default)* — `#e0e5ec` — neutral, balanced, the canonical Neumorphic tone
- **Warm Linen** — `#e8e1d9` — warm and organic, feels tactile and premium
- **Slate Mist** — `#d8dce6` — cooler, technical, sterile precision
- **Midnight** — `#1e2228` — dark mode, deep charcoal
- **Graphite** — `#282c34` — dark mode, slightly warmer
- **Custom** — user provides a hex

**3. Accent Color**
Used only for active states, progress, and primary CTAs:
- **Lavender** *(default)* — `#9b72cf` — sophisticated, uncommon
- **Coral** — `#f07167` — warm and energetic
- **Teal** — `#00b4d8` — technical, sharp
- **Amber** — `#e9a825` — premium, warm
- **Sage** — `#74a57f` — natural, calm
- **Custom** — user provides a hex

**4. Typography**
- **Modern Geometric** *(default)* — Nunito (headings, rounded letterforms that match the soft aesthetic) + Inter (body)
- **Minimal** — DM Sans (headings) + DM Sans (body) — the same family, extreme restraint
- **Editorial** — Plus Jakarta Sans (headings) + DM Sans (body) — slight contrast

**5. Shadow Intensity**
- **Soft** *(default)* — Subtle, realistic. For refined interfaces.
- **Medium** — More pronounced depth. For dashboards and control panels.
- **Bold** — Strong relief. For hero sections and large cards only.

**6. Animation Level**
- **Subtle** *(default)* — Press feedback on buttons, hover lift, toggle transitions, focus glow on inputs.
- **Expressive** — All of the above, plus scroll reveal with upward drift, knob spin animation.
- **None** — Static.

---

## Step 2: Defaults

| Decision | Default |
|---|---|
| Mode | Light |
| Surface color | `#e0e5ec` (Stone Gray) |
| Accent | `#9b72cf` (Lavender) |
| Typography | Nunito + Inter |
| Shadow intensity | Soft |
| Animations | Subtle |

---

## Step 3: CSS Token System

Always define tokens. Adjust to user's surface color — the shadow values are always derived from the surface.

### Light Mode (Stone Gray `#e0e5ec` — default)

```css
:root {
  /* Surface — every element's bg must match this */
  --surface: #e0e5ec;
  --surface-deep: #d1d9e6;   /* slightly recessed areas */
  --surface-raised: #e8edf4; /* highlight areas */

  /* Shadows — derived from surface color */
  --shadow-light: rgba(255, 255, 255, 0.80);
  --shadow-dark:  rgba(163, 177, 198, 0.60);

  /* Shadow sets by intensity */
  --shadow-soft-raised:  -6px -6px 14px var(--shadow-light),  6px  6px 14px var(--shadow-dark);
  --shadow-soft-flat:    -2px -2px 5px  var(--shadow-light),  2px  2px 5px  var(--shadow-dark);
  --shadow-soft-inset: inset -4px -4px 10px var(--shadow-light), inset 4px 4px 10px var(--shadow-dark);

  --shadow-md-raised:  -8px -8px 18px var(--shadow-light),  8px  8px 18px var(--shadow-dark);
  --shadow-md-inset: inset -6px -6px 14px var(--shadow-light), inset 6px 6px 14px var(--shadow-dark);

  --shadow-bold-raised: -12px -12px 24px var(--shadow-light), 12px 12px 24px var(--shadow-dark);

  /* Accent */
  --accent: #9b72cf;
  --accent-light: rgba(155, 114, 207, 0.20);
  --accent-glow: 0 0 12px rgba(155, 114, 207, 0.30);

  /* Text */
  --text-primary:   #4a5568;
  --text-secondary: #718096;
  --text-muted:     #a0aec0;
  --text-accent:    var(--accent);

  /* Radius */
  --r-sm:   8px;
  --r-md:  14px;
  --r-lg:  20px;
  --r-xl:  28px;
  --r-pill: 999px;
  --r-circle: 50%;

  /* Transitions */
  --t-press: 0.12s cubic-bezier(0.4, 0, 0.2, 1);
  --t-lift:  0.22s cubic-bezier(0.34, 1.56, 0.64, 1);
  --t-smooth: 0.25s ease;
}
```

### Dark Mode (Midnight `#1e2228`)

```css
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1e2228;
    --surface-deep: #181c22;
    --surface-raised: #252b33;

    --shadow-light: rgba(50, 60, 75, 0.70);
    --shadow-dark:  rgba(0, 0, 0, 0.50);

    --text-primary:   #c8d0e7;
    --text-secondary: #8892a4;
    --text-muted:     #5a6478;
  }
}
```

---

## Step 4: Component Patterns

### Card (Raised)

```css
.neu-card {
  background: var(--surface);
  border-radius: var(--r-lg);
  box-shadow: var(--shadow-soft-raised);
  padding: 28px;
  border: none; /* NEVER use borders in Neumorphism */
}

.neu-card:hover {
  box-shadow: var(--shadow-md-raised);
  transition: box-shadow var(--t-smooth);
}
```

### Button (Raised → Pressed)

```css
.neu-btn {
  background: var(--surface);
  border: none;
  border-radius: var(--r-md);
  box-shadow: var(--shadow-soft-raised);
  color: var(--text-secondary);
  cursor: pointer;
  font-weight: 600;
  letter-spacing: 0.03em;
  padding: 12px 28px;
  transition: box-shadow var(--t-press), transform var(--t-press), color var(--t-smooth);
}

.neu-btn:hover {
  color: var(--text-primary);
}

.neu-btn:active,
.neu-btn.is-active {
  box-shadow: var(--shadow-soft-inset);
  transform: scale(0.98);
  color: var(--accent);
}

/* Primary CTA — accent fill, NOT neumorphic (flat buttons are intentional contrast) */
.neu-btn-primary {
  background: var(--accent);
  border-radius: var(--r-md);
  border: none;
  box-shadow: var(--shadow-soft-flat), var(--accent-glow);
  color: #fff;
  font-weight: 700;
  padding: 13px 30px;
  transition: box-shadow var(--t-press), transform var(--t-press);
}

.neu-btn-primary:active {
  transform: scale(0.97);
  box-shadow: var(--shadow-soft-inset);
}
```

### Toggle Switch

```css
.neu-toggle {
  width: 56px; height: 28px;
  background: var(--surface);
  border-radius: var(--r-pill);
  box-shadow: var(--shadow-soft-inset);
  position: relative;
  cursor: pointer;
  transition: box-shadow var(--t-smooth);
}

.neu-toggle::after {
  content: '';
  position: absolute;
  top: 4px; left: 4px;
  width: 20px; height: 20px;
  border-radius: 50%;
  background: var(--surface);
  box-shadow: var(--shadow-soft-raised);
  transition: transform var(--t-lift), background var(--t-smooth), box-shadow var(--t-smooth);
}

.neu-toggle.is-on::after {
  transform: translateX(28px);
  background: var(--accent);
  box-shadow: 0 2px 8px rgba(155, 114, 207, 0.45);
}
```

### Slider / Range

```css
.neu-slider {
  -webkit-appearance: none;
  width: 100%;
  height: 8px;
  background: var(--surface);
  border-radius: var(--r-pill);
  box-shadow: var(--shadow-soft-inset);
  outline: none;
  border: none;
}

.neu-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  width: 22px; height: 22px;
  border-radius: 50%;
  background: var(--surface);
  box-shadow: var(--shadow-soft-raised);
  cursor: pointer;
  transition: box-shadow var(--t-press);
}

.neu-slider::-webkit-slider-thumb:active {
  box-shadow: var(--shadow-soft-inset);
}
```

### Input Field

```css
.neu-input {
  background: var(--surface);
  border: none;
  border-radius: var(--r-md);
  box-shadow: var(--shadow-soft-inset);
  color: var(--text-primary);
  font-size: 0.95rem;
  outline: none;
  padding: 14px 18px;
  transition: box-shadow var(--t-smooth);
  width: 100%;
}

.neu-input::placeholder { color: var(--text-muted); }

.neu-input:focus {
  box-shadow: var(--shadow-soft-inset),
              0 0 0 3px var(--accent-light);
}
```

### Circular Knob / Dial

```css
.neu-knob {
  width: 72px; height: 72px;
  border-radius: 50%;
  background: var(--surface);
  box-shadow: var(--shadow-md-raised);
  position: relative;
  cursor: pointer;
}

.neu-knob::before { /* inner recessed ring */
  content: '';
  position: absolute;
  inset: 10px;
  border-radius: 50%;
  background: var(--surface);
  box-shadow: var(--shadow-soft-inset);
}

.neu-knob::after { /* accent indicator dot */
  content: '';
  position: absolute;
  top: 14px; left: 50%;
  transform: translateX(-50%);
  width: 4px; height: 4px;
  border-radius: 50%;
  background: var(--accent);
}
```

---

## Step 5: Icon Rules (Non-Negotiable)

- **SVG only** — never emoji, never icon fonts, never image icons
- **Style**: Thin outline / stroke. Stroke-width 1.5–2px. No fill.
- **Color**: `var(--text-muted)` idle, `var(--text-secondary)` on hover, `var(--accent)` on active
- **Size**: 20px UI icons, 16px inline, 28–40px for hero/feature icons
- **Never box icons** — no circle container, no card wrapper. Inline in the flow.
- **Recommended paths**: Heroicons, Phosphor, or hand-drawn inline SVG `<path>` elements

```html
<!-- Example: correct inline SVG icon -->
<svg width="20" height="20" viewBox="0 0 24 24" fill="none"
     stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 5v14M5 12l7-7 7 7"/>
</svg>
```

---

## Step 6: Micro-Animations

### Press Feedback (Every Interactive Element)

```css
.neu-interactive {
  transition:
    box-shadow var(--t-press),
    transform  var(--t-press);
}

.neu-interactive:active {
  transform: scale(0.97);
}
```

### Hover Lift (Cards Only)

```css
.neu-card {
  transition: box-shadow var(--t-smooth), transform var(--t-smooth);
}

.neu-card:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-md-raised);
}
```

### Scroll Reveal (Subtle Upward Drift)

```css
.reveal {
  opacity: 0;
  transform: translateY(16px);
  transition: opacity 0.5s ease, transform 0.5s ease;
}

.reveal.is-visible {
  opacity: 1;
  transform: translateY(0);
}
```

```js
const observer = new IntersectionObserver(
  entries => entries.forEach(e => e.isIntersecting && e.target.classList.add('is-visible')),
  { threshold: 0.12 }
);
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
```

### Accent Progress Fill

```css
.neu-progress {
  height: 6px;
  border-radius: var(--r-pill);
  background: var(--surface);
  box-shadow: var(--shadow-soft-inset);
  overflow: hidden;
}

.neu-progress-fill {
  height: 100%;
  border-radius: var(--r-pill);
  background: linear-gradient(90deg, var(--accent), color-mix(in srgb, var(--accent) 60%, #fff));
  transition: width 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
}
```

### Reduced Motion Fallback

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
  .reveal { opacity: 1; transform: none; }
}
```

---

## Step 7: Common AI Mistakes to Avoid

| Wrong | Right |
|---|---|
| Element background is white or different from page | Element bg = `var(--surface)` always |
| Adding `border` to neumorphic elements | No borders. Ever. |
| Shadows too dark / high contrast | Shadows are soft — 15–20% shift from base |
| Accent color everywhere | Accent only on active states and one CTA |
| Pure white background (`#fff`) | Mid-gray surface — `#e0e5ec` minimum |
| Filled/heavy icons | Thin outline SVG icons only |
| Flat elements mixed randomly | Every element is raised, flat, or inset — intentionally |
| Box around icon | Icon sits directly in layout, no container |

---

## Step 8: Typography Reference

| Style | Heading | Body | Google Fonts |
|---|---|---|---|
| Modern Geometric *(default)* | Nunito 700/800 | Inter 400/500 | `Nunito:wght@700;800&family=Inter:wght@400;500` |
| Minimal | DM Sans 600/700 | DM Sans 400 | `DM+Sans:wght@400;600;700` |
| Editorial | Plus Jakarta Sans 700 | DM Sans 400 | `Plus+Jakarta+Sans:wght@700&family=DM+Sans:wght@400` |

```css
h1 { font-size: clamp(2rem, 4.5vw, 3.75rem); font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em; }
h2 { font-size: clamp(1.5rem, 3vw, 2.75rem); font-weight: 700; color: var(--text-primary); }
h3 { font-size: 1.25rem; font-weight: 600; color: var(--text-primary); }
p  { font-size: 1rem; line-height: 1.75; color: var(--text-secondary); }
label, caption { font-size: 0.8rem; font-weight: 600; color: var(--text-muted); letter-spacing: 0.08em; text-transform: uppercase; }
```

---

## Step 9: Output Standards

- Complete, runnable code — no stubs or TODO placeholders
- Single-file HTML unless user specifies a framework; embed all CSS, JS, SVG inline
- SVG icons only — no emoji, no icon containers; icons sit directly in the layout
- Every element background = `var(--surface)` — the most common mistake is using white or off-surface colors
- No borders on neumorphic components — shadows define all edges
- CSS variables throughout — nothing hardcoded outside `:root`
- Responsive — CSS Grid / Flexbox, `clamp()` for fluid type, works at 375px and 1440px
- Comment each section so users can customize shadow values
- Accent used sparingly — one CTA, toggle active state, progress fill. Not on cards or backgrounds.
