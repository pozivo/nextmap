# 🔧 Release Troubleshooting Guide

## Current Situation
- NextMap v0.2.3 is ready with all nmap compatibility features
- GitHub Actions workflow exists but releases are not being created automatically
- Need to ensure users can download binaries

## 🎯 Immediate Solutions

### Option A: Fix GitHub Actions (Automated Future)

1. **Check Repository Settings**
   - Go to GitHub repo → Settings → Actions → General
   - Verify "Allow all actions" is enabled
   - Verify "Read and write permissions" are set

2. **Debug Current Workflow**
   - Check if Actions tab shows any failed runs
   - Look for trigger issues or permission errors

3. **Test Minimal Workflow**
   ```yml
   name: Test Release
   on:
     push:
       tags: [ 'test-*' ]
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - name: Echo
           run: echo "Workflow triggered successfully"
   ```

### Option B: Manual Release (Immediate Solution)

1. **Install Rust** (if not available)
   ```powershell
   # Download and install from https://rustup.rs/
   # Or use winget:
   winget install Rustlang.Rustup
   ```

2. **Build Release Binaries**
   ```powershell
   # Windows x64
   cargo build --release --target x86_64-pc-windows-msvc
   
   # Cross-compile for Linux (if needed)
   rustup target add x86_64-unknown-linux-gnu
   cargo build --release --target x86_64-unknown-linux-gnu
   ```

3. **Create Release Archives**
   ```powershell
   # Create Windows release
   $version = "v0.2.3"
   $windows_dir = "nextmap-$version-windows-x64"
   New-Item -ItemType Directory -Path $windows_dir
   Copy-Item "target\release\nextmap.exe" "$windows_dir\"
   Copy-Item "README.md" "$windows_dir\"
   Copy-Item "LICENSE" "$windows_dir\"
   Compress-Archive -Path $windows_dir -DestinationPath "$windows_dir.zip"
   ```

4. **Upload to GitHub**
   - Go to GitHub repo → Releases → "Create a new release"
   - Tag: v0.2.3
   - Title: "NextMap v0.2.3 - nmap Compatibility & Enhanced UX"
   - Upload the created .zip files

### Option C: Use Existing Debug Binary (Quick Test)

For immediate testing, the debug binary is available:
```
target\debug\nextmap.exe
```

## 🚀 Recommended Action Plan

1. **Immediate**: Create manual release with available binaries
2. **Short-term**: Install Rust and build optimized release binaries  
3. **Long-term**: Fix GitHub Actions for automated future releases

## 📋 GitHub Actions Debugging Checklist

- [ ] Repository has Actions enabled
- [ ] Workflow file syntax is correct
- [ ] Tags are properly pushed to GitHub
- [ ] Repository permissions allow Actions to create releases
- [ ] No conflicts with branch protection rules
- [ ] Secrets/tokens are properly configured

## 🔍 Verification Steps

After creating release:
1. Check GitHub releases page for downloadable files
2. Download and test binary on clean system
3. Verify all features work as expected
4. Update installation instructions in README

---

**Next Action**: Choose Option A, B, or C based on urgency and available tools.