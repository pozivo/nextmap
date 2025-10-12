@echo off
echo 🔍 GitHub Actions Error Analysis for NextMap v0.2.4
echo Run ID: 18446552994
echo Repository: pozivo/nextmap
echo.

echo 📋 Common Error Patterns to Look For:
echo.
echo 1. BUILD ERRORS (Most Likely):
echo    ❌ "error: failed to run custom build command for openssl-sys"
echo    ❌ "Could not find directory of OpenSSL installation"  
echo    ❌ "pkg-config has not been configured to support cross-compilation"
echo    💡 Solution: OpenSSL should work on GitHub runners (not Windows cross-compile)
echo.
echo 2. ARCHIVE CREATION ERRORS:
echo    ❌ "7z: command not found" (Windows)
echo    ❌ "tar: command not found" (Unix)  
echo    ❌ "The system cannot find the path specified"
echo    💡 Solution: Commands should be available on GitHub runners
echo.
echo 3. ARTIFACT UPLOAD ERRORS:
echo    ❌ "No files were found with the provided path"
echo    ❌ "upload-artifact action failed"
echo    💡 Solution: Check file paths and artifacts creation
echo.
echo 4. RELEASE CREATION ERRORS:
echo    ❌ "No artifacts found"
echo    ❌ "Error: Resource not accessible by integration"
echo    💡 Solution: Verify GITHUB_TOKEN permissions
echo.

echo 🎯 Specific URLs to Check:
echo Actions Run: https://github.com/pozivo/nextmap/actions/runs/18446552994
echo Each Job Log: Click on individual job names to see detailed logs
echo.

echo 🔧 Quick Fixes Based on Error Type:
echo If OpenSSL errors: Expected on cross-compile, should work on native runners
echo If 7z errors: Switch to PowerShell Compress-Archive for Windows
echo If artifact errors: Fix file paths in workflow
echo If release errors: Check GITHUB_TOKEN permissions
echo.

echo 📊 Expected Successful Outcome:
echo - 5 build jobs complete (Windows, Linux x2, macOS x2)
echo - 1 release job creates GitHub release with 5 downloadable files
echo.

echo 🚀 Next Steps:
echo 1. Open the workflow run URL above
echo 2. Click on any failed jobs (red X)
echo 3. Expand failed steps to see error details  
echo 4. Report specific error messages for targeted fixes
echo.

pause