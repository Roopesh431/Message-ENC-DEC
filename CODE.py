import tkinter as tk
from tkinter import messagebox, scrolledtext
import json
import time
import os
import sys

# --- Cipher Logic (Same as before, integrated into the class) ---

def encode_message_logic(text, key):
    """Core logic to encode a message."""
    encoded_parts = []
    for char in text:
        ascii_val = ord(char)
        encoded_val = ascii_val * key
        binary_val = bin(encoded_val)[2:]
        encoded_parts.append(binary_val)
    return " ".join(encoded_parts)

def decode_message_logic(encoded_code, key):
    """Core logic to decode a message."""
    decoded_message = []
    binary_chunks = encoded_code.strip().split(" ")

    for binary_str in binary_chunks:
        if not binary_str:
            continue
        try:
            encoded_val = int(binary_str, 2)
            original_ascii = encoded_val // key

            # Integrity Check
            if encoded_val % key != 0:
                return None, f"Error: Chunk '{binary_str}' ({encoded_val}) is not divisible by key ({key})."

            decoded_char = chr(original_ascii)
            decoded_message.append(decoded_char)

        except ValueError:
            return None, "Error: Invalid binary format found in the code."
        except Exception as e:
            return None, f"Unexpected error during decoding: {e}"

    return "".join(decoded_message), None

# --- Application Class ---

class MessageCipherApp:
    HISTORY_FILE = "cipher_history.json"

    def __init__(self, master):
        self.master = master
        master.title("Message Encoder and Decoder")
        master.geometry("800x600")
        master.configure(bg="#f4f4f9")

        # History list
        self.history = self.load_history()

        # Configure layout (Main frames: Left for Input/Result, Right for History)
        self.main_frame = tk.Frame(master, bg="#f4f4f9", padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.grid_columnconfigure(0, weight=1) # Input/Result column
        self.main_frame.grid_columnconfigure(1, weight=1) # History column
        self.main_frame.grid_rowconfigure(0, weight=1)

        self._create_input_result_frame()
        self._create_history_frame()

        # Load initial history view
        self._update_history_display()

    def _create_input_result_frame(self):
        """Creates the frame for user inputs, controls, and final result."""
        input_frame = tk.Frame(self.main_frame, bg="#ffffff", padx=15, pady=15, bd=2, relief="groove")
        input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        input_frame.grid_columnconfigure(0, weight=1)

        # Title
        tk.Label(input_frame, text="Secret Message", font=("Helvetica", 16, "bold"), bg="#ffffff", fg="#333333").grid(row=0, column=0, pady=(0, 15), sticky="w")

        # --- Input Field (Text/Code) ---
        tk.Label(input_frame, text="Message / Encoded Code:", font=("Helvetica", 10), bg="#ffffff", fg="#555555").grid(row=1, column=0, sticky="w")

        self.input_text = scrolledtext.ScrolledText(input_frame, height=5, font=("Courier", 10), relief="solid", bd=1)
        self.input_text.grid(row=2, column=0, sticky="ew", pady=(5, 10))

        # --- Key Input ---
        key_frame = tk.Frame(input_frame, bg="#ffffff")
        key_frame.grid(row=3, column=0, sticky="ew", pady=(5, 10))
        key_frame.grid_columnconfigure(1, weight=1)

        tk.Label(key_frame, text="Key (Positive Integer):", font=("Helvetica", 10), bg="#ffffff", fg="#555555").grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.key_var = tk.StringVar(value="12")
        self.key_entry = tk.Entry(key_frame, textvariable=self.key_var, width=10, font=("Helvetica", 10), relief="solid", bd=1)
        self.key_entry.grid(row=0, column=1, sticky="w")

        # --- Control Buttons ---
        button_frame = tk.Frame(input_frame, bg="#ffffff")
        button_frame.grid(row=4, column=0, sticky="ew", pady=(10, 15))

        tk.Button(button_frame, text="🔐 Encode Message", command=lambda: self.run_operation("Encode"),
                  bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"), relief="raised", bd=2).pack(side=tk.LEFT, padx=5, ipadx=10)

        tk.Button(button_frame, text="🔓 Decode Code", command=lambda: self.run_operation("Decode"),
                  bg="#FF9800", fg="white", font=("Helvetica", 10, "bold"), relief="raised", bd=2).pack(side=tk.LEFT, padx=5, ipadx=10)

        # --- Result Display ---
        tk.Label(input_frame, text="Result (Code / Message):", font=("Helvetica", 10), bg="#ffffff", fg="#555555").grid(row=5, column=0, sticky="w", pady=(10, 0))

        self.result_text = scrolledtext.ScrolledText(input_frame, height=5, font=("Courier", 10), bg="#e8e8e8", relief="solid", bd=1, state=tk.DISABLED)
        self.result_text.grid(row=6, column=0, sticky="ew", pady=(5, 10))

        # --- Copy Button ---
        self.copy_button = tk.Button(input_frame, text="📋 Copy Result", command=self.copy_result,
                                      bg="#2196F3", fg="white", font=("Helvetica", 10, "bold"), relief="raised", bd=2, state=tk.DISABLED)
        self.copy_button.grid(row=7, column=0, sticky="w", pady=(0, 5))


    def _create_history_frame(self):
        """Creates the frame for displaying the operation history."""
        history_frame = tk.Frame(self.main_frame, bg="#ffffff", padx=15, pady=15, bd=2, relief="groove")
        history_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        history_frame.grid_columnconfigure(0, weight=1)
        history_frame.grid_rowconfigure(1, weight=1)

        tk.Label(history_frame, text="Operation History", font=("Helvetica", 16, "bold"), bg="#ffffff", fg="#333333").grid(row=0, column=0, sticky="w", pady=(0, 10))

        # History Listbox
        self.history_listbox = tk.Listbox(history_frame, font=("Courier", 9), relief="flat", bd=1, selectmode=tk.SINGLE, bg="#f9f9f9")
        self.history_listbox.grid(row=1, column=0, sticky="nsew", pady=(0, 5))

        # Add a scrollbar to the listbox
        scrollbar = tk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_listbox.yview)
        scrollbar.grid(row=1, column=0, sticky="nse", pady=(0, 5))
        self.history_listbox.config(yscrollcommand=scrollbar.set)

        # Optional: Add a button to clear history
        tk.Button(history_frame, text="🧹 Clear History", command=self.clear_history,
                  bg="#F44336", fg="white", font=("Helvetica", 10), relief="raised", bd=2).grid(row=2, column=0, sticky="w", pady=(5, 0))

    # --- Persistence Logic (Saving/Loading History to JSON file) ---

    def load_history(self):
        """Loads history from a local JSON file."""
        if os.path.exists(self.HISTORY_FILE):
            try:
                with open(self.HISTORY_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print("History file corrupted. Starting with a blank history.")
                return []
        return []

    def save_history(self):
        """Saves current history to a local JSON file."""
        with open(self.HISTORY_FILE, 'w') as f:
            json.dump(self.history, f, indent=4)

    def _update_history_display(self):
        """Clears and repopulates the history listbox."""
        self.history_listbox.delete(0, tk.END)
        for entry in reversed(self.history): # Show newest first
            timestamp = entry.get('time', 'Unknown')
            operation = entry.get('operation', 'OP')
            result_preview = entry.get('result', '...').replace('\n', ' ')

            # Format the entry for the listbox
            display_text = f"[{timestamp}] {operation}: {result_preview[:50]}..."
            self.history_listbox.insert(tk.END, display_text)

    def add_to_history(self, operation, input_data, key, result):
        """Adds a new entry to history and updates persistence."""
        new_entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "operation": operation,
            "input": input_data,
            "key": key,
            "result": result
        }
        self.history.append(new_entry)
        self.save_history()
        self._update_history_display()

    def clear_history(self):
        """Clears the history from memory, file, and display."""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all operation history? This cannot be undone."):
            self.history = []
            if os.path.exists(self.HISTORY_FILE):
                os.remove(self.HISTORY_FILE)
            self._update_history_display()
            messagebox.showinfo("Success", "History cleared.")

    # --- Control Logic ---

    def get_input_and_key(self):
        """Retrieves input text and validates the key."""
        input_data = self.input_text.get("1.0", tk.END).strip()
        key_str = self.key_var.get().strip()

        if not input_data:
            messagebox.showerror("Input Error", "The message or encoded code field cannot be empty.")
            return None, None

        try:
            key = int(key_str)
            if key <= 0:
                messagebox.showerror("Input Error", "The key must be a positive whole number.")
                return None, None
            return input_data, key
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid whole number for the key.")
            return None, None

    def set_result(self, text, is_success):
        """Updates the result text area and copy button state."""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state=tk.DISABLED)

        if is_success:
            self.copy_button.config(state=tk.NORMAL, text="📋 Copy Result")
        else:
            self.copy_button.config(state=tk.DISABLED, text="Operation Failed")

    def run_operation(self, operation):
        """Handles the main encode/decode workflow."""
        input_data, key = self.get_input_and_key()
        if input_data is None:
            return

        result = None
        error = None

        if operation == "Encode":
            result = encode_message_logic(input_data, key)

        elif operation == "Decode":
            result, error = decode_message_logic(input_data, key)

        if error:
            self.set_result(error, False)
        else:
            self.set_result(result, True)
            self.add_to_history(operation, input_data, key, result)

    def copy_result(self):
        """Copies the content of the result field to the clipboard."""
        result = self.result_text.get("1.0", tk.END).strip()
        if result:
            self.master.clipboard_clear()
            self.master.clipboard_append(result)
            self.copy_button.config(text="✅ Copied!")
            self.master.after(2000, lambda: self.copy_button.config(text="📋 Copy Result")) # Reset button text

# --- Main Execution ---

if __name__ == "__main__":
    # Check if we are running in a specific environment that might redirect stdout
    # By using the standard tkinter event loop, this is ready to run.

    root = tk.Tk()
    app = MessageCipherApp(root)
    root.mainloop()
