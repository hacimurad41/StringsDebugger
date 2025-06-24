import os
import subprocess
from capstone import *
import tkinter as tk
from tkinter import filedialog
import pefile

def dosya_sec():
    root = tk.Tk()
    root.withdraw()
    dosya_yolu = filedialog.askopenfilename(
        title="Bir EXE dosyası seçin",
        filetypes=[("EXE Dosyaları", "*.exe")]
    )
    return dosya_yolu

def oku_stringler(dosya_yolu):
    print("\n[1] EXE içindeki okunabilir metinler (string'ler):\n")
    try:
        with open(dosya_yolu, "rb") as f:
            veri = f.read()

        yazi = ""
        for b in veri:
            if 32 <= b < 127:
                yazi += chr(b)
            else:
                if len(yazi) > 4:
                    print(yazi)
                yazi = ""
    except Exception as e:
        print(f"Hata oluştu (string çıkarma): {e}")

def disassemble_exe(dosya_yolu):
    print("\n[2] Disassembler (Assembly Çıktısı - İlk 1000 byte):\n")
    try:
        with open(dosya_yolu, "rb") as f:
            data = f.read()

        md = Cs(CS_ARCH_X86, CS_MODE_32)  # Gerekirse 64-bit yap: CS_MODE_64
        for i in md.disasm(data[:1000], 0x1000):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    except Exception as e:
        print(f"Hata oluştu (disassembler): {e}")

def pyinstaller_coz(dosya_yolu):
    print("\n[3] PyInstaller EXE Çözümleme:\n")
    try:
        if not os.path.exists("pyinstxtractor.py"):
            print("❌ pyinstxtractor.py bulunamadı. Aynı klasöre koymalısın.")
            return

        komut = f"python pyinstxtractor.py \"{dosya_yolu}\""
        subprocess.run(komut, shell=True)

        klasor = dosya_yolu.split("/")[-1] + "_extracted"
        if os.path.exists(klasor):
            print(f"[+] Çıkarılan klasör: {klasor}")
            for root, _, files in os.walk(klasor):
                for f in files:
                    if f.endswith(".pyc"):
                        pyc_yolu = os.path.join(root, f)
                        print(f"[-] .pyc bulundu: {pyc_yolu}")
                        print("[-] uncompyle6 ile kaynak koda çeviriliyor:\n")
                        subprocess.run(f"uncompyle6 \"{pyc_yolu}\"", shell=True)
        else:
            print("PyInstaller çıkarımı başarısız veya Python EXE değil.")
    except Exception as e:
        print(f"Hata oluştu (pyinstaller): {e}")

def ana_program():
    print("🔍 EXE Kod Açığa Çıkarıcı v2.0")
    dosya = dosya_sec()
    if not dosya:
        print("İşlem iptal edildi.")
        return

    oku_stringler(dosya)
    disassemble_exe(dosya)
    pyinstaller_coz(dosya)

ana_program()
