#!/usr/bin/env python3
"""
Deep System & Developer Cache Cleaner for macOS
Safely purges ephemeral scratch files, build artifacts, browser caches,
Darwin per-user temp/cache folders, Apple Neural Engine caches, and
benchmark dumps without removing installed software or configurations.
"""

import os
import sys
import glob
import shutil
import stat
import subprocess

GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def get_avail_space_gb():
    st = os.statvfs("/")
    return (st.f_bavail * st.f_frsize) / (1024**3)

def format_size(bytes_num):
    if bytes_num >= 1024**3:
        return f"{bytes_num / (1024**3):.2f} GB"
    elif bytes_num >= 1024**2:
        return f"{bytes_num / (1024**2):.2f} MB"
    elif bytes_num >= 1024:
        return f"{bytes_num / 1024:.2f} KB"
    return f"{bytes_num} B"

def clean_dir(path):
    freed = 0
    if not os.path.exists(path):
        return 0
    try:
        for r, d, files in os.walk(path):
            for f in files:
                fp = os.path.join(r, f)
                if not os.path.islink(fp):
                    try:
                        freed += os.path.getsize(fp)
                    except Exception:
                        pass
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
    return freed

def main():
    print(f"\n{BOLD}{CYAN}=== Deep System & Cache Cleanup ==={RESET}\n")
    before_gb = get_avail_space_gb()
    print(f"Initial Available Disk Space: {BOLD}{before_gb:.2f} GB{RESET}\n")

    user_uid = os.getuid()
    total_freed = 0

    # 1. Clean Apple Neural Engine / mediaanalysisd ML bundle cache
    print(f"[*] Scanning Apple Neural Engine ML bundle cache...")
    ane_cache = os.path.expanduser("~/Library/Containers/com.apple.mediaanalysisd/Data/Library/Caches/com.apple.mediaanalysisd/com.apple.e5rt.e5bundlecache")
    if os.path.exists(ane_cache):
        ane_freed = clean_dir(ane_cache)
        print(f"    {GREEN}✔{RESET} Removed Apple ML e5bundlecache ({format_size(ane_freed)})")
        total_freed += ane_freed
    else:
        print(f"    - Apple ML e5bundlecache clean")

    # 2. Clean OpenIGI benchmark screenshots (.bmp dumps)
    print(f"[*] Scanning OpenIGI engine benchmark screenshots...")
    openigi_pattern = os.path.expanduser("~/Library/Application Support/OpenIGI/engine/shot_*.bmp")
    openigi_bmps = glob.glob(openigi_pattern)
    bmp_freed = 0
    for f in openigi_bmps:
        try:
            sz = os.path.getsize(f)
            os.remove(f)
            bmp_freed += sz
        except Exception:
            pass
    if bmp_freed > 0:
        print(f"    {GREEN}✔{RESET} Removed {len(openigi_bmps)} benchmark screenshots ({format_size(bmp_freed)})")
    else:
        print(f"    - No OpenIGI frame screenshots to clean")
    total_freed += bmp_freed

    # 3. Clean Google Chrome on-device AI model weights
    print(f"[*] Scanning Chrome on-device AI model cache...")
    chrome_model = os.path.expanduser("~/Library/Application Support/Google/Chrome/OptGuideOnDeviceModel")
    if os.path.exists(chrome_model):
        model_freed = clean_dir(chrome_model)
        print(f"    {GREEN}✔{RESET} Cleared OptGuideOnDeviceModel weights ({format_size(model_freed)})")
        total_freed += model_freed
    else:
        print(f"    - Chrome model cache clean")

    # 4. Clean Google Chrome Web Caches
    print(f"[*] Scanning Google Chrome web caches...")
    chrome_cache = os.path.expanduser("~/Library/Caches/Google/Chrome")
    if os.path.exists(chrome_cache):
        cache_freed = clean_dir(chrome_cache)
        print(f"    {GREEN}✔{RESET} Cleared Chrome web cache ({format_size(cache_freed)})")
        total_freed += cache_freed
    else:
        print(f"    - Chrome web cache clean")

    # 5. Clean user-owned scratch files in /private/tmp
    print(f"[*] Scanning user temporary build artifacts in /private/tmp...")
    tmp_freed = 0
    tmp_count = 0
    for entry in os.scandir("/private/tmp"):
        name = entry.name
        if name.startswith("com.apple.") or name.startswith("powerlog") or name.startswith("."):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
            if st.st_uid != user_uid or stat.S_ISSOCK(st.st_mode):
                continue

            entry_size = 0
            if entry.is_dir(follow_symlinks=False):
                for r, d, files in os.walk(entry.path):
                    for f in files:
                        fp = os.path.join(r, f)
                        if not os.path.islink(fp):
                            try:
                                entry_size += os.path.getsize(fp)
                            except Exception:
                                pass
                shutil.rmtree(entry.path, ignore_errors=True)
            else:
                entry_size = st.st_size
                try:
                    os.remove(entry.path)
                except Exception:
                    pass
            tmp_freed += entry_size
            tmp_count += 1
        except Exception:
            pass
    if tmp_freed > 0:
        print(f"    {GREEN}✔{RESET} Cleared {tmp_count} scratch items from /private/tmp ({format_size(tmp_freed)})")
    else:
        print(f"    - /private/tmp clean")
    total_freed += tmp_freed

    # 6. Clean Darwin per-user temporary directory ($TMPDIR)
    print(f"[*] Scanning Darwin user temporary directory ($TMPDIR)...")
    try:
        darwin_tmp = subprocess.run(["getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True).stdout.strip()
        if darwin_tmp and os.path.exists(darwin_tmp):
            d_freed = 0
            d_count = 0
            for item in os.listdir(darwin_tmp):
                if item.startswith("tmp") or item.startswith("igi-layout") or item in ["recomp-guest", "guest.cpp", "node-compile-cache", "jiti"] or item.startswith("MSau_"):
                    full = os.path.join(darwin_tmp, item)
                    try:
                        if os.path.isdir(full):
                            sz = sum(os.path.getsize(os.path.join(r, f)) for r, d, files in os.walk(full) for f in files if not os.path.islink(os.path.join(r, f)))
                            shutil.rmtree(full, ignore_errors=True)
                        else:
                            sz = os.path.getsize(full)
                            os.remove(full)
                        d_freed += sz
                        d_count += 1
                    except Exception:
                        pass
            if d_freed > 0:
                print(f"    {GREEN}✔{RESET} Cleared {d_count} build/recomp scratch items ({format_size(d_freed)})")
            else:
                print(f"    - Darwin TMPDIR clean")
            total_freed += d_freed
    except Exception:
        pass

    # 7. Clean Darwin per-user cache directory (DARWIN_USER_CACHE_DIR)
    print(f"[*] Scanning Darwin user cache directory ($CACHEDIR)...")
    try:
        darwin_cache = subprocess.run(["getconf", "DARWIN_USER_CACHE_DIR"], capture_output=True, text=True).stdout.strip()
        if darwin_cache and os.path.exists(darwin_cache):
            dc_freed = 0
            for target in ["com.google.Chrome.helper", "org.python.python", "org.openigi.desktop", "clangd"]:
                full = os.path.join(darwin_cache, target)
                if os.path.exists(full):
                    sz = clean_dir(full)
                    dc_freed += sz
            if dc_freed > 0:
                print(f"    {GREEN}✔{RESET} Cleared ephemeral app caches ({format_size(dc_freed)})")
            else:
                print(f"    - Darwin CACHEDIR clean")
            total_freed += dc_freed
    except Exception:
        pass

    # 8. Clean .NET NuGet package caches
    if shutil.which("dotnet"):
        print(f"[*] Clearing .NET NuGet local caches...")
        try:
            res = subprocess.run(["dotnet", "nuget", "locals", "all", "--clear"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                print(f"    {GREEN}✔{RESET} NuGet package caches cleared")
            else:
                print(f"    - NuGet clean")
        except Exception:
            pass

    # 9. Clean Python pip cache
    print(f"[*] Purging Python pip cache...")
    try:
        res = subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], capture_output=True, text=True)
        if res.returncode == 0 and "Files removed:" in res.stdout:
            summary = [l.strip() for l in res.stdout.splitlines() if "Files removed:" in l]
            print(f"    {GREEN}✔{RESET} {summary[0] if summary else 'Pip cache purged'}")
        else:
            print(f"    - Pip cache clean")
    except Exception:
        print(f"    - Skipped pip")

    # 10. Clean NPM cache
    if shutil.which("npm"):
        print(f"[*] Cleaning NPM cache...")
        try:
            subprocess.run(["npm", "cache", "clean", "--force"], capture_output=True, text=True, check=False)
            print(f"    {GREEN}✔{RESET} NPM cache purged")
        except Exception:
            pass

    # 11. Homebrew download cache
    if shutil.which("brew"):
        print(f"[*] Cleaning Homebrew download cache...")
        try:
            subprocess.run(["brew", "cleanup", "-s", "--prune=all"], capture_output=True, text=True, check=False)
            print(f"    {GREEN}✔{RESET} Homebrew download cache pruned")
        except Exception:
            pass

    # Summary
    after_gb = get_avail_space_gb()
    print(f"\n{BOLD}{GREEN}=== Cleanup Complete ==={RESET}")
    print(f"Total Direct Space Removed : {BOLD}{format_size(total_freed)}{RESET}")
    print(f"Previous Available Space   : {before_gb:.2f} GB")
    print(f"Current Available Space    : {BOLD}{after_gb:.2f} GB{RESET} (Gain: +{max(0.0, after_gb - before_gb):.2f} GB)\n")

if __name__ == "__main__":
    main()
