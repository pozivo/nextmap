# 🔧 Potential GitHub Actions Fixes

## Issue #1: OpenSSL Cross-Compilation (Most Likely)

### Problem
```
error: failed to run custom build command for `openssl-sys v0.9.109`
Could not find directory of OpenSSL installation
```

### Solution: Add OpenSSL setup to workflow

```yml
# Add to Linux jobs
- name: Install OpenSSL development packages
  if: matrix.os == 'ubuntu-latest'
  run: |
    sudo apt-get update
    sudo apt-get install -y pkg-config libssl-dev

# Add to macOS jobs  
- name: Install OpenSSL (macOS)
  if: matrix.os == 'macos-latest'
  run: |
    brew install openssl pkg-config
    echo "OPENSSL_DIR=$(brew --prefix openssl)" >> $GITHUB_ENV
```

## Issue #2: Windows Archive Creation

### Problem
```
7z: command not found
```

### Solution: Use PowerShell instead

```yml
- name: Create archive (Windows)
  if: matrix.os == 'windows-latest'
  run: |
    mkdir release
    copy target\${{ matrix.target }}\release\nextmap.exe release\
    copy README.md release\ 2>nul || echo README.md not found
    copy LICENSE release\ 2>nul || echo LICENSE not found
    cd release
    powershell -command "Compress-Archive -Path * -DestinationPath ..\${{ matrix.asset_name }}"
```

## Issue #3: Missing Dependencies

### Problem
```
Package not found: pkg-config
```

### Solution: Install build dependencies

```yml
- name: Install build dependencies (Linux)
  if: matrix.target == 'x86_64-unknown-linux-musl'
  run: |
    sudo apt-get update
    sudo apt-get install -y musl-tools musl-dev pkg-config libssl-dev
```

## Issue #4: File Path Issues

### Problem
```
No files were found with the provided path
```

### Solution: Debug and fix paths

```yml
- name: Debug artifacts
  run: |
    ls -la
    ls -la target/
    ls -la target/${{ matrix.target }}/release/ || true
    
- name: Upload Release Asset
  uses: actions/upload-artifact@v4
  with:
    name: ${{ matrix.name }}
    path: ${{ matrix.asset_name }}
    if-no-files-found: error
```

## 🚀 Complete Fixed Workflow Snippet

```yml
    - name: Install dependencies (Linux)
      if: matrix.os == 'ubuntu-latest'
      run: |
        sudo apt-get update
        sudo apt-get install -y pkg-config libssl-dev
        
    - name: Install musl tools (Linux musl only)
      if: matrix.target == 'x86_64-unknown-linux-musl'
      run: |
        sudo apt-get install -y musl-tools musl-dev
        
    - name: Install OpenSSL (macOS)
      if: matrix.os == 'macos-latest'
      run: |
        brew install openssl pkg-config
        echo "PKG_CONFIG_PATH=$(brew --prefix openssl)/lib/pkgconfig" >> $GITHUB_ENV
        
    - name: Build binary
      run: cargo build --release --target ${{ matrix.target }}
      
    - name: Create archive (Windows) 
      if: matrix.os == 'windows-latest'
      run: |
        mkdir release
        copy target\${{ matrix.target }}\release\nextmap.exe release\
        copy README.md release\ 2>nul || echo README.md not found
        copy LICENSE release\ 2>nul || echo LICENSE not found
        cd release
        powershell -command "Compress-Archive -Path * -DestinationPath ..\${{ matrix.asset_name }}"
```

---

**Apply these fixes based on the specific errors you see in the workflow logs.**