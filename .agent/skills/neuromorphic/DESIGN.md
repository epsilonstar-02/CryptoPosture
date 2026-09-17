# Design Guidelines — Neumorphism / Soft UI

Synthesized from production-grade Neumorphic UI reference kits (light mode variants, dark mode variant, and minimal editorial variant).

---

## Visual Style
- **Aesthetic**: Soft materiality — elements appear physically extruded from or pressed into a unified surface. No flat design, no glass, no gradients as backgrounds.
- **Mood**: Tactile, refined, restrained. Feels like premium molded plastic or soft clay under diffuse studio lighting.
- **Inspiration**: Dribbble Neumorphism era (2019–2020), refined toward production quality. Closer to analog control panels than digital dashboards.

---

## Color Palette

### Light Mode (canonical)
- **Surface / Background**: `#e0e5ec` — every element's bg must match this exactly
- **Surface Variant (deep)**: `#d1d9e6` — slightly recessed areas, inset wells
- **Surface Variant (raised)**: `#e8edf4` — subtle highlight on protruding forms
- **Shadow Light**: `rgba(255, 255, 255, 0.80)` — cast toward top-left (light source)
- **Shadow Dark**: `rgba(163, 177, 198, 0.60)` — cast toward bottom-right
- **Text Primary**: `#4a5568`
- **Text Secondary**: `#718096`
- **Text Muted**: `#a0aec0`
- **Accent (Image 1)**: Lavender-purple gradient `#9b72cf` → `#c084fc` — active states, CTAs, progress fills
- **Accent (Image 2)**: Orange `#f97316` — toggles, sliders, bar chart fills
- **Accent (Image 3)**: Cyan/teal `#00b4d8` — active elements on dark surface
- **Accent (Image 4)**: None — fully monochromatic, no accent

> Default recommendation: `#9b72cf` (lavender). Accent appears only on active/selected states — never as a background fill or card color.

### Dark Mode (Image 3)
- **Surface**: `#1e2228` (deep charcoal, not pure black)
- **Shadow Light**: `rgba(50, 60, 75, 0.70)`
- **Shadow Dark**: `rgba(0, 0, 0, 0.50)`
- **Text Primary**: `#c8d0e7`
- **Text Secondary**: `#8892a4`
- **Accent**: `#00b4d8` (cyan)

---

## Typography
- **Primary Font (Images 1–3)**: Geometric sans-serif — similar to Nunito, DM Sans, or Poppins. Rounded terminals match the soft aesthetic.
- **Primary Font (Image 4)**: Thin/light geometric sans — similar to Inter Light or DM Sans 300. Extremely minimal.
- **Headings**: Medium–Bold (500–700), tight letter-spacing (`-0.01em` to `-0.02em`)
- **Body**: Regular (400), `1rem`, line-height `1.65–1.75`, muted text color
- **Labels / Captions**: Small (`0.75–0.8rem`), uppercase, letter-spacing `0.08em`, muted color
- **Monospace**: Not used in any reference

---

## Spacing & Layout
- **Overall feel**: Airy — elements have generous breathing room, never crowded
- **Card padding**: `24–32px` internal padding on all sides
- **Component gap**: `16–24px` between sibling elements
- **Control spacing**: Knobs, toggles, and buttons spaced with `12–16px` gaps
- **Grid**: Flexible multi-column for control panels; single-column centered for dashboards
- **Base unit**: `8px` — all spacing is a multiple of 8

---

## Borders & Radius
- **Border radius**: 
  - Small buttons / inputs: `10–12px`
  - Cards / panels: `16–20px`
  - Large hero cards: `24–28px`
  - Pill / toggles: `999px`
  - Knobs / avatars: `50%`
- **Borders**: **None** — borders are never used. Shadow alone defines all edges. This is a hard rule of the style.

---

## Shadows & Elevation

The entire visual system is built on a single dual-shadow formula. Both shadows originate from the same element; no separate layer is needed.

```css
/* Raised — element protrudes */
box-shadow:
  -6px -6px 14px rgba(255, 255, 255, 0.80),
   6px  6px 14px rgba(163, 177, 198, 0.60);

/* Inset / Pressed — element is pushed in */
box-shadow:
  inset -4px -4px 10px rgba(255, 255, 255, 0.80),
  inset  4px  4px 10px rgba(163, 177, 198, 0.60);

/* Flat — minimal depth */
box-shadow:
  -2px -2px 5px rgba(255, 255, 255, 0.80),
   2px  2px 5px rgba(163, 177, 198, 0.60);
```

- Shadow contrast is **always subtle** — 15–20% lighter/darker than the surface. High-contrast shadows look broken.
- Light shadow = top-left. Dark shadow = bottom-right. Always.
- Interactive elements transition from raised (idle) → inset (active/pressed).

---

## Buttons
- **Raised (default idle state)**: Surface bg, dual raised shadows, rounded corners, medium-weight label in muted text
- **Pressed (active state)**: Inset shadow, slight scale-down (`0.97–0.98`), accent-colored label
- **Primary CTA**: Flat accent-colored fill (`var(--accent)`), white label, subtle accent glow — intentionally breaks the neumorphic mold to create contrast
- **Hover**: Slightly darker text, shadow intensifies marginally
- **No borders on any button variant**

---

## Icons
- **Style**: Thin outline / stroke SVG — stroke-width `1.5–2px`, no fill
- **Sources observed**: Heroicons-style, Phosphor-style line icons
- **Size**: `20px` standard UI, `16px` inline text, `28–40px` feature/hero
- **Color**: Muted text color idle (`#a0aec0`), secondary on hover, accent on active
- **Never boxed** — icons sit directly in the layout, no circle container, no card wrapper
- **No emoji** used anywhere in any reference

---

## Components Spotted

- **Cards**: Large rounded panels, raised shadow, `24–32px` padding, surface-matched background
- **Knobs / Dials**: Circular, concentric raised outer + inset inner ring, accent indicator dot at top
- **Toggles**: Pill-shaped inset track, raised circular thumb that slides; thumb turns accent color when active
- **Sliders**: Inset pill track, raised circular thumb; accent-colored fill on the active portion
- **Icon Buttons**: Small rounded-square or circular, raised shadow, inset on press
- **Progress Rings**: Circular stroke progress, accent-colored arc on dark or light surface
- **Profile Cards**: Raised card with avatar, label, and a single accent CTA button inside
- **Bar Charts (Image 2)**: Bars are raised neumorphic pill shapes; active bar filled with accent color
- **Dropdowns**: Pill-shaped raised container, chevron icon, inset on open state
- **Navigation Tabs**: Row of raised buttons; selected tab becomes inset with accent label
- **Input Fields**: Inset shadow, no border, placeholder in muted color, accent focus ring on focus

---

## Imagery & Illustration
- No photography used in any reference
- Minimal iconography — thin outline SVGs only
- Image 3 uses a circular avatar photo clipped in a raised circular frame
- Image 4 uses a small album art thumbnail inside a raised card — the only decorative image

---

## Overall Replication Notes

- **Surface color is everything** — use `#e0e5ec` as the page background and as every element's background. Deviating breaks the illusion immediately.
- **No white backgrounds** — pure white (`#fff`) is the single most common mistake. The surface must be mid-gray.
- **Accent is rationed** — one accent color, used only on active/selected states, progress fills, and the primary CTA. 90% of the UI is achromatic.
- **No borders anywhere** — the shadow defines every edge. Adding a border destroys the material illusion.
- **Shadows must be soft** — keep dark shadow opacity at `0.5–0.65`, light shadow at `0.75–0.85`. Avoid harsh contrast.
- **Rounded shapes always** — minimum `10px` radius on interactive elements; pill for toggles; circles for knobs/avatars.
- **Three states, used intentionally**: raised (idle), flat (neutral/informational), inset (active/pressed). Every element has a state.
- **Typography is restrained** — one font family, two weights maximum per context. Labels uppercase and spaced.
- **Spacing is generous** — never crowd neumorphic elements; shadows need breathing room to read correctly.
