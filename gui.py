import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import os
from scanner import start_scan, start_subnet_scan
from PIL import Image, ImageTk

os.makedirs("results", exist_ok=True)

def threaded_scan():
    target = entry_target.get()
    try:
        start_port = int(entry_start.get())
        end_port = int(entry_end.get())
    except ValueError:
        messagebox.showerror("Input Error", "Ports must be integers.")
        return

    if not target:
        messagebox.showerror("Input Error", "Please enter a target IP or domain or subnet.")
        return

    text_output.delete("1.0", tk.END)
    scan_button.config(state=tk.DISABLED)
    threading.Thread(target=execute_scan, args=(target, start_port, end_port), daemon=True).start()

def execute_scan(target, start_port, end_port):
    if "/" in target:
        start_subnet_scan(target, start_port, end_port, 100, update_text)
    else:
        start_scan(target, start_port, end_port, 100, update_text)
    update_text("Scan Complete. Check generated graph and logs.")
    show_graph()
    scan_button.config(state=tk.NORMAL)

def update_text(message):
    text_output.insert(tk.END, message + "\n")
    text_output.see(tk.END)

def show_graph():
    try:
        graph_window = tk.Toplevel(root)
        graph_window.title("Scan Graph Result")
        img = Image.open("results/port_scan_graph.png")
        img = img.resize((500, 300))
        img = ImageTk.PhotoImage(img)
        panel = tk.Label(graph_window, image=img)
        panel.image = img
        panel.pack()
    except Exception as e:
        update_text(f"Could not load graph image: {e}")

root = tk.Tk()
root.title("Advanced Python Port & Subnet Scanner")
root.geometry("600x500")

frame_inputs = tk.Frame(root)
frame_inputs.pack(pady=10)

tk.Label(frame_inputs, text="Target IP / Domain / Subnet (CIDR):").grid(row=0, column=0, sticky="e")
entry_target = tk.Entry(frame_inputs, width=30)
entry_target.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame_inputs, text="Start Port:").grid(row=1, column=0, sticky="e")
entry_start = tk.Entry(frame_inputs, width=10)
entry_start.grid(row=1, column=1, sticky="w", padx=5, pady=5)

entry_start.insert(0, "20")

tk.Label(frame_inputs, text="End Port:").grid(row=2, column=0, sticky="e")
entry_end = tk.Entry(frame_inputs, width=10)
entry_end.grid(row=2, column=1, sticky="w", padx=5, pady=5)

entry_end.insert(0, "100")

scan_button = tk.Button(root, text="Start Scan", command=threaded_scan, bg="green", fg="white")
scan_button.pack(pady=10)

text_output = scrolledtext.ScrolledText(root, height=15, width=70)
text_output.pack(padx=10, pady=10)

root.mainloop()
