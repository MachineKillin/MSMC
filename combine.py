import tkinter as tk
from tkinter import filedialog

def combine_files():
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    file_paths = filedialog.askopenfilenames(title="Select files", filetypes=[("Text files", "*.txt")])
    
    combined_content = set()
    
    for file_path in file_paths:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            combined_content.update(lines)
    
    with open('combos.txt', 'w', encoding='utf-8') as output_file:
        for line in sorted(combined_content):
            output_file.write(line)

    print("Files combined successfully into 'combos.txt'.")

if __name__ == "__main__":
    combine_files()