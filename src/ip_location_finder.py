import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
from tkintertable import TableCanvas, TableModel
from .utils import create_tooltip
from .ip_services import fetch_ipinfo_details, fetch_ipapi_details, fetch_geoip2_details
import logging

class IPLocationFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Location Finder")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')

        self.cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.current_page = 1
        self.rows_per_page = 10

        self.original_df = pd.DataFrame()

        self.create_widgets()
        self.update_cache_stats()

    def create_widgets(self):
        self.create_input_frame()
        self.create_button_frame()
        self.create_service_frame()
        self.create_status_frame()
        self.create_search_frame()
        self.create_filter_frame()
        self.create_pagination_frame()
        self.create_table_frame()

    def create_input_frame(self):
        input_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        input_frame.pack(fill='x')
        tk.Label(input_frame, text="Enter IP addresses (comma, tab, or newline separated):", bg='#f0f0f0').pack(anchor='w', padx=10)
        self.ip_entry = tk.Text(input_frame, height=5, width=80)
        self.ip_entry.pack(padx=10)

    def create_button_frame(self):
        button_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        button_frame.pack(fill='x')
        tk.Button(button_frame, text="Fetch Details", command=self.on_fetch_button_click, bg='#4caf50', fg='white').pack(side='left', padx=5, pady=5)
        tk.Button(button_frame, text="Save as CSV/Excel", command=lambda: self.save_file(None), bg='#2196f3', fg='white').pack(side='left', padx=5, pady=5)
        tk.Button(button_frame, text="Load IPs from File", command=self.load_ip_addresses, bg='#ff9800', fg='white').pack(side='left', padx=5, pady=5)
        tk.Button(button_frame, text="Clear Cache", command=self.clear_cache, bg='#f44336', fg='white').pack(side='left', padx=5, pady=5)

    def create_service_frame(self):
        service_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        service_frame.pack(fill='x')
        tk.Label(service_frame, text="Select IP Location Service:", bg='#f0f0f0').pack(anchor='w', padx=10)
        self.service_var = tk.StringVar(value="ipinfo")
        tk.Radiobutton(service_frame, text="ipinfo", variable=self.service_var, value="ipinfo", bg='#f0f0f0').pack(side='left', padx=5, pady=5)
        tk.Radiobutton(service_frame, text="ipapi", variable=self.service_var, value="ipapi", bg='#f0f0f0').pack(side='left', padx=5, pady=5)
        tk.Radiobutton(service_frame, text="geoip2", variable=self.service_var, value="geoip2", bg='#f0f0f0').pack(side='left', padx=5, pady=5)

    def create_status_frame(self):
        status_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        status_frame.pack(fill='x')
        self.status_label = tk.Label(status_frame, text="Status: Ready", bg='#f0f0f0')
        self.status_label.pack(side='left', padx=10)
        self.progress = ttk.Progressbar(status_frame, length=200, mode='determinate')
        self.progress.pack(side='left', padx=10)
        self.cache_stats_label = tk.Label(status_frame, text="Cache Hits: 0 | Cache Misses: 0", bg='#f0f0f0')
        self.cache_stats_label.pack(side='left', padx=10)

    def create_search_frame(self):
        search_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        search_frame.pack(fill='x')
        tk.Label(search_frame, text="Search:", bg='#f0f0f0').pack(side='left', padx=10)
        self.search_entry = tk.Entry(search_frame)
        self.search_entry.pack(side='left', padx=5, pady=5)
        tk.Button(search_frame, text="Search", command=lambda: self.save_file(self.search_table()), bg='#673ab7', fg='white').pack(side='left', padx=5, pady=5)
        tk.Button(search_frame, text="Reset Filters", command=self.reset_filters, bg='#607d8b', fg='white').pack(side='left', padx=5, pady=5)

    def create_filter_frame(self):
        filter_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        filter_frame.pack(fill='x')
        tk.Label(filter_frame, text="Filter Column:", bg='#f0f0f0').pack(side='left', padx=10)
        self.column_var = tk.StringVar()
        self.column_menu = ttk.Combobox(filter_frame, textvariable=self.column_var)
        self.column_menu['values'] = ["IP Address", "City", "Region", "Country", "Postal", "Timezone", "Latitude", "Longitude"]
        self.column_menu.pack(side='left', padx=5, pady=5)
        tk.Label(filter_frame, text="Criteria:", bg='#f0f0f0').pack(side='left', padx=10)
        self.criteria_entry = tk.Entry(filter_frame)
        self.criteria_entry.pack(side='left', padx=5, pady=5)
        tk.Button(filter_frame, text="Filter", command=lambda: self.save_file(self.advanced_filter_table()), bg='#3f51b5', fg='white').pack(side='left', padx=5, pady=5)

        create_tooltip(self.column_menu, "Select the column you want to filter.")
        create_tooltip(self.criteria_entry, "Enter the criteria to filter the selected column.")

    def create_pagination_frame(self):
        pagination_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        pagination_frame.pack(fill='x')
        self.prev_button = tk.Button(pagination_frame, text="Previous", command=self.prev_page, bg='#009688', fg='white')
        self.prev_button.pack(side='left', padx=5, pady=5)
        self.next_button = tk.Button(pagination_frame, text="Next", command=self.next_page, bg='#009688', fg='white')
        self.next_button.pack(side='left', padx=5, pady=5)

    def create_table_frame(self):
        table_frame = tk.Frame(self.root, bg='#f0f0f0')
        table_frame.pack(fill='both', expand=True)
        self.table_canvas = TableCanvas(table_frame)
        self.table_canvas.show()

    def on_fetch_button_click(self):
        ip_addresses = self.ip_entry.get("1.0", tk.END)
        if not ip_addresses.strip():
            messagebox.showerror("Input Error", "Please enter at least one IP address.")
            return
        self.progress['value'] = 0
        self.status_label.config(text="Starting fetch...")
        logging.info("Starting fetch process")
        self.root.update_idletasks()

        selected_service = self.service_var.get()
        if selected_service == "ipinfo":
            self.original_df = fetch_ipinfo_details(ip_addresses, self.cache, self.progress, self.status_label, self.root)
        elif selected_service == "ipapi":
            self.original_df = fetch_ipapi_details(ip_addresses, self.cache, self.progress, self.status_label, self.root)
        elif selected_service == "geoip2":
            self.original_df = fetch_geoip2_details(ip_addresses, self.cache, self.progress, self.status_label, self.root)
        
        self.update_table(self.original_df)
        self.status_label.config(text="Fetch completed.")
        logging.info("Fetch process completed")

    def update_table(self, dataframe, page=1):
        self.current_page = page
        start_row = (page - 1) * self.rows_per_page
        end_row = start_row + self.rows_per_page
        paginated_df = dataframe.iloc[start_row:end_row]
        table_model = TableModel(paginated_df)
        self.table_canvas.updateModel(table_model)
        self.table_canvas.redraw()
        self.update_pagination_buttons()

    def update_pagination_buttons(self):
        if self.current_page == 1:
            self.prev_button.config(state=tk.DISABLED)
        else:
            self.prev_button.config(state=tk.NORMAL)

        if self.current_page * self.rows_per_page >= len(self.original_df):
            self.next_button.config(state=tk.DISABLED)
        else:
            self.next_button.config(state=tk.NORMAL)

    def save_file(self, filtered_df=None):
        filetypes = [('CSV files', '*.csv'), ('Excel files', '*.xlsx')]
        filepath = filedialog.asksaveasfilename(filetypes=filetypes, defaultextension=filetypes)
        if filepath:
            dataframe = filtered_df if filtered_df is not None else self.original_df
            try:
                if filepath.endswith('.csv'):
                    dataframe.to_csv(filepath, index=False)
                else:
                    dataframe.to_excel(filepath, index=False)
                messagebox.showinfo("Save Successful", f"File saved to {filepath}")
                logging.info(f"File saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {e}")
                logging.error(f"Failed to save file: {filepath}. Error: {e}")

    def clear_cache(self):
        self.cache.clear()
        self.cache_hits = 0
        self.cache_misses = 0
        self.update_cache_stats()
        logging.info("Cache cleared")
        messagebox.showinfo("Cache Cleared", "The cache has been cleared successfully.")

    def update_cache_stats(self):
        self.cache_stats_label.config(text=f"Cache Hits: {self.cache_hits} | Cache Misses: {self.cache_misses}")

    def load_ip_addresses(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            try:
                with open(filepath, 'r') as file:
                    ip_addresses = file.read()
                    self.ip_entry.delete("1.0", tk.END)
                    self.ip_entry.insert(tk.END, ip_addresses)
                logging.info(f"IP addresses loaded from file: {filepath}")
            except Exception as e:
                messagebox.showerror("File Error", f"Failed to load file: {e}")
                logging.error(f"Failed to load file: {filepath}. Error: {e}")

    def search_table(self):
        query = self.search_entry.get()
        filtered_df = self.original_df[self.original_df.apply(lambda row: row.astype(str).str.contains(query, case=False).any(), axis=1)]
        self.update_table(filtered_df)
        return filtered_df

    def advanced_filter_table(self):
        column = self.column_var.get()
        criteria = self.criteria_entry.get()
        if column and criteria:
            filtered_df = self.original_df[self.original_df[column].astype(str).str.contains(criteria, case=False)]
            self.update_table(filtered_df)
            return filtered_df

    def reset_filters(self):
        self.update_table(self.original_df)

    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.update_table(self.original_df, page=self.current_page)

    def next_page(self):
        if self.current_page * self.rows_per_page < len(self.original_df):
            self.current_page += 1
            self.update_table(self.original_df, page=self.current_page)

if __name__ == "__main__":
    logging.basicConfig(filename='logs/ip_location_finder.log', level=logging.INFO, 
                        format='%(asctime)s - %(levelname)s - %(message)s')
    root = tk.Tk()
    app = IPLocationFinderApp(root)
    root.mainloop()
