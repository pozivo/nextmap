# NextMap Assets Guide

This directory contains visual assets for NextMap releases and documentation.

## Files

### 📸 Release Images

- **`release-cover.svg`** - Main release cover image (1200x630px)
  - Use for GitHub releases, social media sharing
  - Features comprehensive overview of v0.2.0 capabilities
  
- **`logo-banner.svg`** - Compact banner for README (800x400px)
  - Embedded in main README.md
  - Shows key features and example command

- **`demo-screenshot.svg`** - Terminal demo simulation (900x600px)
  - Shows NextMap in action with realistic output
  - Perfect for documentation and tutorials

### 📝 Text Assets

- **`banner.md`** - ASCII art banner with feature highlights
  - Can be used in terminal documentation
  - Contains structured feature breakdown

## Usage for Releases

### GitHub Release Cover

1. Upload `release-cover.svg` as the primary image for each release
2. Add it to the release description with:

   ```markdown
   ![NextMap v0.2.0](assets/release-cover.svg)
   ```

### Social Media

- Use `release-cover.svg` for announcements
- Perfect dimensions for GitHub social preview
- Professional gradient design with feature highlights

### Documentation

- `demo-screenshot.svg` shows realistic usage
- `logo-banner.svg` provides clean branding
- All images use consistent color scheme

## Design Elements

### Color Palette

- **Primary**: `#06b6d4` (Cyan) → `#8b5cf6` (Purple) gradient
- **Background**: `#0f172a` → `#334155` dark gradient  
- **Text**: `#e2e8f0` (light) / `#64748b` (muted)
- **Accents**:
  - Stealth: `#8b5cf6` (Purple)
  - CVE: `#06b6d4` (Cyan)
  - Performance: `#10b981` (Green)
  - Professional: `#f59e0b` (Amber)

### Typography

- **Headlines**: Arial Black (bold, impactful)
- **Body**: Arial (clean, readable)
- **Code**: Consolas/SF Mono (monospace)

### Features Highlighted

1. 🥷 **Stealth Scanning** - Ghost, Ninja, Shadow modes
2. 🛡️ **CVE Detection** - NIST integration, auto-scanning
3. ⚡ **Full Port Scanning** - 1-65535 default, multi-format output
4. 🎯 **Enterprise Ready** - JSON, XML, CSV, Markdown support

## Updating for Future Releases

When creating new release assets:

1. Update version numbers in all SVG files
2. Add new features to the highlights
3. Maintain consistent design language
4. Test social media preview on GitHub
5. Ensure accessibility with sufficient contrast

## File Formats

All images are SVG for:

- ✅ **Scalability** - Perfect at any size
- ✅ **Small file size** - Fast loading
- ✅ **GitHub compatibility** - Native support
- ✅ **Editability** - Easy to modify text/colors
- ✅ **Professional quality** - Crisp at all resolutions