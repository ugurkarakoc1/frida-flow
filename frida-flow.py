#!/usr/bin/env python3
"""
FridaFlow - Otomatik Frida Server Kurulum Aracı
Mobile Security Testing | Android
"""

import subprocess
import sys
import os
import json
import urllib.request
import lzma
import time
import tempfile


def ensure_rich():
    try:
        import rich  # noqa: F401
    except ImportError:
        print("[*] 'rich' yükleniyor...")
        subprocess.run([sys.executable, "-m", "pip", "install", "rich", "--quiet"], check=True)


ensure_rich()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn,
    BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
)
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.align import Align
from rich import box
from rich.rule import Rule

console = Console()

# ─── Sabitler ────────────────────────────────────────────────────────────────

FRIDA_DEVICE_PATH = "/data/local/tmp/frida-server"
GITHUB_API        = "https://api.github.com/repos/frida/frida/releases/latest"

BANNER = r"""
[bold green]
 ███████╗██████╗ ██╗██████╗  █████╗    ███████╗██╗      ██████╗ ██╗    ██╗
 ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗   ██╔════╝██║     ██╔═══██╗██║    ██║
 █████╗  ██████╔╝██║██║  ██║███████║   █████╗  ██║     ██║   ██║██║ █╗ ██║
 ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║   ██╔══╝  ██║     ██║   ██║██║███╗██║
 ██║     ██║  ██║██║██████╔╝██║  ██║   ██║     ███████╗╚██████╔╝╚███╔███╔╝
 ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝
[/bold green]"""

# Frida mimari adları (seçim → frida release adı)
ARCH_OPTIONS = [
    ("1", "x86",    "x86",    "Emülatör / Intel 32-bit"),
    ("2", "x86_64", "x86_64", "Emülatör / Intel 64-bit"),
    ("3", "arm",    "arm",    "Eski cihazlar (ARMv7)"),
    ("4", "arm64",  "arm64",  "Modern cihazlar (ARMv8 / arm64-v8a)"),
]

# ADB abi → seçim no
ABI_TO_CHOICE = {
    "x86":         "1",
    "x86_64":      "2",
    "armeabi":     "3",
    "armeabi-v7a": "3",
    "arm64-v8a":   "4",
}

# ─── ADB Yardımcıları ─────────────────────────────────────────────────────────

def adb(*args, timeout=30) -> subprocess.CompletedProcess:
    return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)


def check_adb() -> bool:
    try:
        r = subprocess.run(["adb", "version"], capture_output=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def get_connected_devices() -> list[dict]:
    r = adb("devices", "-l")
    devices = []
    for line in r.stdout.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            info = dict(p.split(":", 1) for p in parts[2:] if ":" in p)
            devices.append({"serial": parts[0], "info": info})
    return devices


def get_device_abi(serial: str) -> str:
    r = adb("-s", serial, "shell", "getprop", "ro.product.cpu.abi")
    return r.stdout.strip()


def get_device_info(serial: str) -> dict:
    props = {
        "model":   "ro.product.model",
        "android": "ro.build.version.release",
        "sdk":     "ro.build.version.sdk",
    }
    info = {}
    for key, prop in props.items():
        r = adb("-s", serial, "shell", "getprop", prop)
        info[key] = r.stdout.strip() or "?"
    return info


def has_root(serial: str) -> bool:
    r = adb("-s", serial, "shell", "su -c id")
    return "uid=0" in r.stdout or "root" in r.stdout


# ─── GitHub / İndirme ────────────────────────────────────────────────────────

FALLBACK_VERSION = "16.7.19"


def get_local_frida_version() -> str | None:
    """PC'de kurulu frida client versiyonunu döndür, yoksa None."""
    try:
        r = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def fetch_release(tag: str) -> tuple[str, list]:
    """Belirli bir tag için release bilgisi al (örn. '16.7.19')."""
    url = f"https://api.github.com/repos/frida/frida/releases/tags/{tag}"
    req = urllib.request.Request(url, headers={"User-Agent": "FridaFlow/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    return data["tag_name"].lstrip("v"), data["assets"]


def fetch_latest_release() -> tuple[str, list]:
    req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "FridaFlow/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    version = data["tag_name"].lstrip("v")
    return version, data["assets"]


def find_asset(assets: list, arch: str, version: str) -> tuple[str | None, str | None]:
    target = f"frida-server-{version}-android-{arch}.xz"
    for a in assets:
        if a["name"] == target:
            return a["browser_download_url"], a["name"]
    return None, None


def download_file(url: str, dest: str):
    req = urllib.request.Request(url, headers={"User-Agent": "FridaFlow/1.0"})
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(complete_style="green", finished_style="bold green"),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("Frida server indiriliyor", total=None)
        with urllib.request.urlopen(req) as resp:
            total = resp.headers.get("Content-Length")
            if total:
                prog.update(task, total=int(total))
            with open(dest, "wb") as f:
                done = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    prog.update(task, completed=done)


# ─── UI Yardımcıları ─────────────────────────────────────────────────────────

def ok(msg: str):
    console.print(f"  [bold green]✓[/bold green] {msg}")


def step(msg: str):
    console.print(f"  [bold yellow]⟳[/bold yellow] {msg}")


def err(msg: str):
    console.print(f"  [bold red]✗[/bold red] {msg}")


def info(msg: str):
    console.print(f"  [dim cyan]i[/dim cyan] [dim]{msg}[/dim]")


def section(title: str):
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]"))
    console.print()


# ─── Ana Akış ────────────────────────────────────────────────────────────────

def print_banner():
    console.clear()
    console.print(BANNER)
    console.print(
        Align.center(
            Panel(
                "[bold cyan]Mobile Security Testing — Otomatik Frida Server Kurulum Aracı[/bold cyan]\n"
                "[dim]Android Frida Otomatik Kurulum  •  FridaFlow v1.0[/dim]",
                border_style="bright_green",
                padding=(0, 6),
            )
        )
    )


def step_check_adb():
    section("Sistem Kontrolü")
    step("ADB kontrol ediliyor...")
    if not check_adb():
        err("ADB bulunamadı! Lütfen [bold]android-tools-adb[/bold] veya Android SDK kurun.")
        sys.exit(1)
    ok("ADB hazır")


def step_select_device() -> str:
    step("Bağlı cihazlar taranıyor...")
    devices = get_connected_devices()

    if not devices:
        console.print()
        console.print(
            Panel(
                "[red bold]Bağlı Android cihaz bulunamadı![/red bold]\n\n"
                "[dim]Lütfen kontrol edin:[/dim]\n"
                "  • USB Debugging (Geliştirici Ayarları) açık mı?\n"
                "  • Cihaz USB ile bağlı / emülatör çalışıyor mu?\n"
                "  • [bold]adb devices[/bold] komutunu çalıştırın",
                border_style="red",
                title="[red]Hata[/red]",
            )
        )
        sys.exit(1)

    ok(f"{len(devices)} cihaz bulundu")
    console.print()

    if len(devices) == 1:
        serial = devices[0]["serial"]
        info(f"Tek cihaz seçildi → {serial}")
        return serial

    section("Cihaz Seçimi")
    t = Table(box=box.ROUNDED, border_style="cyan", show_header=True, header_style="bold cyan")
    t.add_column("#",       width=4,  style="bold yellow")
    t.add_column("Serial",  style="green")
    t.add_column("Model",   style="cyan")
    t.add_column("Transport")

    for i, d in enumerate(devices, 1):
        inf = d["info"]
        t.add_row(str(i), d["serial"], inf.get("model", "?"), inf.get("transport_id", "-"))

    console.print(t)
    choice = IntPrompt.ask("[yellow]Cihaz numarası[/yellow]", default=1)
    choice = max(1, min(choice, len(devices)))
    return devices[choice - 1]["serial"]


def step_device_info(serial: str):
    section("Cihaz Bilgisi")
    step("Cihaz bilgileri alınıyor...")
    inf = get_device_info(serial)
    rooted = has_root(serial)

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold cyan")
    t.add_column(style="green")
    t.add_row("Seri No",    serial)
    t.add_row("Model",      inf["model"])
    t.add_row("Android",    inf["android"])
    t.add_row("SDK",        inf["sdk"])
    t.add_row("Root",       "[bold green]Var[/bold green]" if rooted else "[yellow]Yok (su denenemedi)[/yellow]")
    console.print(t)
    return rooted


def step_select_arch(serial: str) -> str:
    section("Mimari Seçimi")
    step("Cihaz mimarisi tespit ediliyor...")
    abi = get_device_abi(serial)
    default_choice = ABI_TO_CHOICE.get(abi, "4")
    if abi:
        ok(f"Tespit edilen ABI: [bold]{abi}[/bold]")
    else:
        info("ABI tespit edilemedi, varsayılan arm64 kullanılacak")

    console.print()
    t = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
    t.add_column("#",        width=4,  style="bold yellow")
    t.add_column("Mimari",             style="green")
    t.add_column("Açıklama")

    for num, label, _, desc in ARCH_OPTIONS:
        marker = "  [bold green]← otomatik tespit[/bold green]" if num == default_choice and abi else ""
        t.add_row(num, label, desc + marker)

    console.print(t)
    choice = Prompt.ask(
        "[yellow]Mimari seçin[/yellow]",
        choices=["1", "2", "3", "4"],
        default=default_choice,
    )

    _, label, frida_arch, _ = next(o for o in ARCH_OPTIONS if o[0] == choice)
    ok(f"Seçilen mimari: [bold cyan]{label}[/bold cyan]")
    return frida_arch


def step_fetch_frida(frida_arch: str) -> tuple[str, str, str]:
    section("Frida Sürümü")

    # PC'deki frida versiyonunu kontrol et
    local_ver = get_local_frida_version()
    if local_ver:
        step(f"PC'de frida bulundu → [bold cyan]{local_ver}[/bold cyan] sürümü kullanılacak")
        target_tag = local_ver
        source_label = f"PC'deki sürümle eşleştirildi ({local_ver})"
    else:
        step(f"PC'de frida bulunamadı → fallback sürüm kullanılacak: [bold cyan]{FALLBACK_VERSION}[/bold cyan]")
        target_tag = FALLBACK_VERSION
        source_label = f"Varsayılan fallback sürümü ({FALLBACK_VERSION})"

    try:
        version, assets = fetch_release(target_tag)
    except Exception as e:
        err(f"GitHub API erişilemedi: {e}")
        sys.exit(1)

    ok(f"{source_label} → [bold green]{version}[/bold green]")

    url, filename = find_asset(assets, frida_arch, version)
    if not url:
        err(f"[bold]{frida_arch}[/bold] için frida-server bulunamadı! (v{version})")
        console.print(
            f"\n  [dim]Beklenen dosya: frida-server-{version}-android-{frida_arch}.xz[/dim]"
        )
        sys.exit(1)

    info(f"Paket: {filename}")
    return version, url, filename


def step_confirm(serial: str, version: str, frida_arch: str) -> bool:
    console.print()
    t = Table(box=box.ROUNDED, border_style="bright_green", show_header=False, padding=(0, 3))
    t.add_column(style="bold cyan")
    t.add_column(style="bold white")
    t.add_row("Hedef Cihaz",    serial)
    t.add_row("Frida Sürümü",   version)
    t.add_row("Mimari",         frida_arch)
    t.add_row("Kurulum Yolu",   FRIDA_DEVICE_PATH)
    console.print(Panel(t, title="[bold]Kurulum Özeti[/bold]", border_style="green"))
    console.print()
    return Confirm.ask("[yellow]Kuruluma devam edilsin mi?[/yellow]", default=True)


def step_install(serial: str, url: str, filename: str):
    section("Kurulum")

    with tempfile.TemporaryDirectory() as tmp:
        xz_path     = os.path.join(tmp, filename)
        binary_path = os.path.join(tmp, "frida-server")

        # 1) İndir
        download_file(url, xz_path)
        ok("İndirme tamamlandı")

        # 2) XZ aç
        step("Arşiv açılıyor...")
        try:
            with lzma.open(xz_path) as src, open(binary_path, "wb") as dst:
                dst.write(src.read())
            ok("Arşiv açıldı")
        except Exception as e:
            err(f"Arşiv açılamadı: {e}")
            sys.exit(1)

        # 3) Mevcut instance'ı durdur
        step("Önceki frida-server durduruluyor...")
        adb("-s", serial, "shell", "pkill -f frida-server")
        time.sleep(1)
        ok("Önceki instance temizlendi")

        # 4) ADB push
        step("Cihaza kopyalanıyor...")
        r = adb("-s", serial, "push", binary_path, FRIDA_DEVICE_PATH, timeout=60)
        if r.returncode != 0:
            err(f"Push hatası: {r.stderr.strip()}")
            sys.exit(1)
        ok("Cihaza kopyalandı")

        # 5) chmod
        step("Çalıştırma izni ayarlanıyor...")
        r = adb("-s", serial, "shell", f"chmod 755 {FRIDA_DEVICE_PATH}")
        if r.returncode != 0:
            err(f"chmod hatası: {r.stderr.strip()}")
            sys.exit(1)
        ok("İzinler ayarlandı")


def step_start(serial: str, rooted: bool):
    console.print()
    if not Confirm.ask("  [yellow]Frida server şimdi başlatılsın mı?[/yellow]", default=True):
        return

    section("Başlatma")

    # SELinux permissive (root varsa)
    if rooted:
        step("SELinux geçici olarak permissive yapılıyor...")
        adb("-s", serial, "shell", "su -c 'setenforce 0'")
        ok("SELinux → permissive")

    # Port forwarding
    step("Port yönlendirme yapılıyor (27042 / 27043)...")
    adb("-s", serial, "forward", "tcp:27042", "tcp:27042")
    adb("-s", serial, "forward", "tcp:27043", "tcp:27043")
    ok("Port yönlendirme aktif")

    # Başlat
    step("Frida server başlatılıyor...")
    if rooted:
        cmd = f"su -c 'nohup {FRIDA_DEVICE_PATH} > /dev/null 2>&1 &'"
    else:
        cmd = f"nohup {FRIDA_DEVICE_PATH} > /dev/null 2>&1 &"
    adb("-s", serial, "shell", cmd)
    time.sleep(2)

    # Doğrula
    step("Doğrulanıyor...")
    r = adb("-s", serial, "shell", "ps -A | grep frida-server")
    if "frida-server" in r.stdout:
        ok("[bold green]Frida server başarıyla çalışıyor![/bold green]")
    else:
        console.print("  [yellow]?[/yellow] Frida server durumu belirsiz. Manuel kontrol:")
        info(f"adb -s {serial} shell ps -A | grep frida-server")


def print_success(serial: str, version: str, frida_arch: str):
    console.print()
    console.print(
        Panel(
            f"[bold green]Kurulum başarıyla tamamlandı![/bold green]\n\n"
            f"[cyan]Sürüm   :[/cyan]  {version}\n"
            f"[cyan]Mimari  :[/cyan]  {frida_arch}\n"
            f"[cyan]Cihaz   :[/cyan]  {serial}\n"
            f"[cyan]Konum   :[/cyan]  {FRIDA_DEVICE_PATH}\n\n"
            f"[dim]── Hızlı Kullanım ──────────────────────────────[/dim]\n"
            f"  [bold]frida-ps -U[/bold]              → Çalışan uygulamalar\n"
            f"  [bold]frida -U -f <paket>[/bold]     → Uygulama başlat & attach\n"
            f"  [bold]frida -U <pid>[/bold]           → PID ile attach\n"
            f"  [bold]frida-ls-devices[/bold]         → Bağlı cihazları göster",
            title="[bold green] Tamamlandı[/bold green]",
            border_style="bright_green",
            padding=(1, 3),
        )
    )


# ─── Giriş Noktası ───────────────────────────────────────────────────────────

def main():
    print_banner()

    step_check_adb()

    serial  = step_select_device()
    rooted  = step_device_info(serial)
    arch    = step_select_arch(serial)
    version, url, filename = step_fetch_frida(arch)

    if not step_confirm(serial, version, arch):
        console.print("\n[dim]İptal edildi.[/dim]\n")
        sys.exit(0)

    step_install(serial, url, filename)
    step_start(serial, rooted)
    print_success(serial, version, arch)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Kullanıcı tarafından iptal edildi.[/yellow]\n")
        sys.exit(0)
    except Exception as exc:
        console.print(f"\n[red bold]Beklenmeyen hata:[/red bold] {exc}\n")
        raise
