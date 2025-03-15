import re
import os
import tkinter as tk
from tkinter import filedialog, ttk
import threading
from datetime import datetime
import concurrent.futures
import itertools
from PIL import Image, ImageTk  # Добавлено для работы с изображениями

def extract_email(line):
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    found = re.search(email_pattern, line)
    return found.group(0) if found else None

def process_chunk(chunk, queries_set):
    results = {query: [] for query in queries_set}
    counts = {query: 0 for query in queries_set}
    for line in chunk:
        line_lower = line.lower()
        for query in queries_set:
            if query in line_lower:
                results[query].append(line)
                counts[query] += 1
    return results, counts

def filter_lines(input_file, output_dir, queries, progress_var, stats_label, root, num_threads):
    try:
        queries_set = set(query.strip().lower() for query in queries.split(','))
        total_lines = 0
        processed_lines = 0
        chunk_size = 1000
        results = {query: [] for query in queries_set}
        counts = {query: 0 for query in queries_set}
        timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        stats_label.config(text="Загрузка файла...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            total_lines = sum(1 for _ in infile)
        progress_var.set(0)
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                chunks = []
                while True:
                    chunk = list(itertools.islice(infile, chunk_size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                futures = [executor.submit(process_chunk, chunk, queries_set) for chunk in chunks]
                for future in concurrent.futures.as_completed(futures):
                    chunk_results, chunk_counts = future.result()
                    for query in queries_set:
                        results[query].extend(chunk_results[query])
                        counts[query] += chunk_counts[query]
                    processed_lines += sum(chunk_counts.values())
                    progress_var.set((processed_lines / total_lines) * 100)
                    stats = "\n".join([f"{query}: {counts[query]}" for query in queries_set])
                    stats_label.config(text=f"Статистика:\n{stats}")
                    root.update_idletasks()
        for query, lines in results.items():
            output_file = os.path.join(output_dir, f"{query}_{timestamp}.txt")
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.writelines(lines)
        stats = "\n".join([f"{query}: {counts[query]}" for query in queries_set])
        stats_label.config(text=f"Статистика:\n{stats}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_filtering(input_file, output_dir, queries, progress_var, stats_label, root):
    if not input_file or not output_dir or not queries:
        stats_label.config(text="Ошибка: Укажите файл, папку и запросы")
        return
    num_threads = tk.simpledialog.askinteger("Количество потоков", "Введите количество потоков (1 или больше):")
    if not num_threads or num_threads <= 0:
        stats_label.config(text="Некорректное количество потоков")
        return
    stats_label.config(text="Поиск начат...")
    root.update_idletasks()
    thread = threading.Thread(
        target=filter_lines,
        args=(input_file, output_dir, queries, progress_var, stats_label, root, num_threads),
        daemon=True
    )
    thread.start()

def filter_emails(input_file, progress_var, stats_label, root):
    try:
        total_lines = 0
        processed_lines = 0
        email_lines = []

        output_file = os.path.splitext(input_file)[0] + "_mail.txt"
        stats_label.config(text="Загрузка файла для проверки почты...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            total_lines = sum(1 for _ in infile)
        progress_var.set(0)
        root.update_idletasks()
        stats_label.config(text="Проверка строк на наличие почты...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            for line in infile:
                processed_lines += 1
                if '@' in line:
                    email_lines.append(line)
                progress_var.set((processed_lines / total_lines) * 100)
                root.update_idletasks()
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(email_lines)
        stats_label.config(text=f"Проверка завершена. Найдено строк с почтой: {len(email_lines)}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_email_filtering(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для проверки почты",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    stats_label.config(text="Проверка почты начата...")
    root.update_idletasks()
    thread = threading.Thread(
        target=filter_emails,
        args=(input_file, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def extract_login_pass(input_file, progress_var, stats_label, root):
    try:
        total_lines = 0
        processed_lines = 0
        login_pass_lines = []

        output_file = os.path.splitext(input_file)[0] + "_login_pass.txt"
        stats_label.config(text="Загрузка файла для обработки LOGIN:PASS...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            total_lines = sum(1 for _ in infile)
        progress_var.set(0)
        root.update_idletasks()
        stats_label.config(text="Извлечение LOGIN:PASS...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            for line in infile:
                processed_lines += 1
                match = re.search(r'[^:]+@[^:]+:[^\s]+', line)
                if match:
                    login_pass_lines.append(match.group(0))
                progress_var.set((processed_lines / total_lines) * 100)
                root.update_idletasks()
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(line + '\n' for line in login_pass_lines)
        stats_label.config(text=f"Обработка завершена. Найдено строк: {len(login_pass_lines)}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_login_pass_extraction(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для извлечения LOGIN:PASS",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    stats_label.config(text="Обработка LOGIN:PASS начата...")
    root.update_idletasks()
    thread = threading.Thread(
        target=extract_login_pass,
        args=(input_file, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def remove_duplicates(input_file, progress_var, stats_label, root):
    try:
        total_lines = 0
        processed_lines = 0
        unique_lines = set()

        output_file = os.path.splitext(input_file)[0] + "_unique.txt"
        stats_label.config(text="Загрузка файла для удаления дублей...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            total_lines = sum(1 for _ in infile)
        progress_var.set(0)
        root.update_idletasks()
        stats_label.config(text="Удаление дублей...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            for line in infile:
                processed_lines += 1
                unique_lines.add(line.strip())
                progress_var.set((processed_lines / total_lines) * 100)
                root.update_idletasks()
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(line + '\n' for line in unique_lines)
        stats_label.config(text=f"Удаление дублей завершено. Уникальных строк: {len(unique_lines)}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_remove_duplicates(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для удаления дублей",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    stats_label.config(text="Удаление дублей начато...")
    root.update_idletasks()
    thread = threading.Thread(
        target=remove_duplicates,
        args=(input_file, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def remove_gjn(input_file, progress_var, stats_label, root):
    try:
        total_lines = 0
        processed_lines = 0
        no_gjn_lines = []

        output_file = os.path.splitext(input_file)[0] + "_no_gjn.txt"
        stats_label.config(text="Загрузка файла для удаления GJN...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            total_lines = sum(1 for _ in infile)
        progress_var.set(0)
        root.update_idletasks()
        stats_label.config(text="Удаление GJN из строк...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            for line in infile:
                processed_lines += 1
                clean_line = re.sub(r'\s*-\s*\d+\s*GJN', '', line).strip()
                if clean_line:
                    no_gjn_lines.append(clean_line)
                progress_var.set((processed_lines / total_lines) * 100)
                root.update_idletasks()
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(line + '\n' for line in no_gjn_lines)
        stats_label.config(text=f"Удаление GJN завершено. Обработано строк: {len(no_gjn_lines)}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_remove_gjn(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для удаления GJN",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    stats_label.config(text="Удаление GJN начато...")
    root.update_idletasks()
    thread = threading.Thread(
        target=remove_gjn,
        args=(input_file, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def sort_file(input_file, progress_var, stats_label, root):
    try:
        stats_label.config(text="Сортировка файла начата...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        sorted_lines = sorted(lines, key=lambda x: x.strip().lower())
        output_file = os.path.splitext(input_file)[0] + "_sorted.txt"
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(sorted_lines)
        stats_label.config(text=f"Сортировка завершена. Сохранено в {output_file}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_sort_file(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для сортировки",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    thread = threading.Thread(
        target=sort_file,
        args=(input_file, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def merge_files_ui(file_list, progress_var, stats_label, root):
    try:
        if not file_list:
            stats_label.config(text="Файлы для объединения не выбраны")
            return
        output_file = filedialog.asksaveasfilename(
            title="Сохранить объединенный файл как",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        if not output_file:
            stats_label.config(text="Файл для сохранения не выбран")
            return
        stats_label.config(text="Объединение файлов начато...")
        root.update_idletasks()
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for file in file_list:
                with open(file, 'r', encoding='utf-8') as infile:
                    outfile.writelines(infile.readlines())
        stats_label.config(text=f"Объединение завершено. Сохранено в {output_file}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def add_file_to_merge(file_list, file_listbox, stats_label):
    file_path = filedialog.askopenfilename(
        title="Выберите файл для объединения",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if file_path:
        file_list.append(file_path)
        file_listbox.insert(tk.END, os.path.basename(file_path))
        stats_label.config(text=f"Добавлен файл: {os.path.basename(file_path)}")

def split_file(input_file, parts, progress_var, stats_label, root):
    try:
        stats_label.config(text="Разделение файла начато...")
        root.update_idletasks()
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        total_lines = len(lines)
        chunk_size = total_lines // parts
        for i in range(parts):
            start = i * chunk_size
            end = start + chunk_size if i < parts - 1 else total_lines
            output_file = os.path.splitext(input_file)[0] + f"_part{i + 1}.txt"
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.writelines(lines[start:end])
        stats_label.config(text=f"Разделение завершено. Создано частей: {parts}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_split_file(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для разделения",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    parts = tk.simpledialog.askinteger("Разделение файла", "Введите количество частей:")
    if not parts or parts <= 0:
        stats_label.config(text="Некорректное количество частей")
        return
    thread = threading.Thread(
        target=split_file,
        args=(input_file, parts, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def query_from_logs(input_dir, output_dir, queries, progress_var, stats_label, root):
    try:
        queries = [query.strip().lower() for query in queries.split(',')]
        total_files = 0
        processed_files = 0
        stats_label.config(text="Сканирование папки...")
        root.update_idletasks()
        txt_files = []
        for root_dir, _, files in os.walk(input_dir):
            for file in files:
                if file.endswith('.txt'):
                    txt_files.append(os.path.join(root_dir, file))
        total_files = len(txt_files)
        if total_files == 0:
            stats_label.config(text="Нет текстовых файлов для обработки")
            return
        progress_var.set(0)
        root.update_idletasks()
        stats_label.config(text="Обработка файлов...")
        root.update_idletasks()
        for file_path in txt_files:
            processed_files += 1
            file_contains_query = False
            with open(file_path, 'r', encoding='utf-8', errors='replace') as infile:
                for line in infile:
                    if any(query in line.lower() for query in queries):
                        file_contains_query = True
                        break
            if file_contains_query:
                base_name = os.path.basename(file_path)
                output_file = os.path.join(output_dir, base_name)
                with open(file_path, 'r', encoding='utf-8', errors='replace') as infile, \
                        open(output_file, 'w', encoding='utf-8') as outfile:
                    outfile.writelines(infile.readlines())
            progress_var.set((processed_files / total_files) * 100)
            root.update_idletasks()
        stats_label.config(text=f"Обработка завершена. Обработано файлов: {total_files}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_query_from_logs(progress_var, stats_label, root):
    input_dir = filedialog.askdirectory(title="Выберите папку с логами")
    if not input_dir:
        stats_label.config(text="Папка не выбрана")
        return
    output_dir = filedialog.askdirectory(title="Выберите папку для сохранения результатов")
    if not output_dir:
        stats_label.config(text="Папка для сохранения не выбрана")
        return
    queries = tk.simpledialog.askstring("Запросы", "Введите запросы через запятую:")
    if not queries:
        stats_label.config(text="Запросы не указаны")
        return
    thread = threading.Thread(
        target=query_from_logs,
        args=(input_dir, output_dir, queries, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def parse_ulp_from_logs(input_dir, output_dir, query, progress_var, stats_label, root):
    try:
        total_files = 0
        processed_files = 0
        stats_label.config(text="Сканирование папки...")
        root.update_idletasks()
        txt_files = []
        for root_dir, _, files in os.walk(input_dir):
            for file in files:
                if file.lower() in ["passwords.txt", "all passwords.txt"]:
                    txt_files.append(os.path.join(root_dir, file))
        total_files = len(txt_files)
        if total_files == 0:
            stats_label.config(text="Нет подходящих файлов для обработки")
            return
        progress_var.set(0)
        root.update_idletasks()
        stats_label.config(text="Обработка файлов...")
        root.update_idletasks()
        results = []
        for file_path in txt_files:
            processed_files += 1
            with open(file_path, 'r', encoding='utf-8', errors='replace') as infile:
                lines = infile.readlines()
            for i in range(len(lines)):
                if query.lower() in lines[i].lower() and "URL:" in lines[i]:
                    user_line = next((line for line in lines[i + 1:i + 5] if line.startswith("USER:")), None)
                    pass_line = next((line for line in lines[i + 1:i + 5] if line.startswith("PASS:")), None)
                    if user_line and pass_line:
                        user = user_line.split("USER:")[1].strip()
                        password = pass_line.split("PASS:")[1].strip()
                        results.append(f"{user}:{password}")
            progress_var.set((processed_files / total_files) * 100)
            root.update_idletasks()
        if results:
            output_file = os.path.join(output_dir, f"{query}_results.txt")
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.writelines(line + '\n' for line in results)
        stats_label.config(text=f"Обработка завершена. Найдено записей: {len(results)}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        progress_var.set(100)
        root.update_idletasks()

def start_parse_ulp_from_logs(progress_var, stats_label, root):
    input_dir = filedialog.askdirectory(title="Выберите папку с логами")
    if not input_dir:
        stats_label.config(text="Папка не выбрана")
        return
    output_dir = filedialog.askdirectory(title="Выберите папку для сохранения результатов")
    if not output_dir:
        stats_label.config(text="Папка для сохранения не выбрана")
        return
    query = tk.simpledialog.askstring("Запрос", "Введите запрос")
    if not query:
        stats_label.config(text="Запрос не указан")
        return
    thread = threading.Thread(
        target=parse_ulp_from_logs,
        args=(input_dir, output_dir, query, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def extract_email_credentials(line):
    credentials = re.search(r'[^:]+:([^:]+:[^:\s]+)$', line)
    if credentials:
        return credentials.group(1)
    credentials = re.search(r'https?://[^/]+/[^/]+/[^/]+\s+([^:]+:[^:\s]+)', line)
    if credentials:
        return credentials.group(1)
    credentials = re.search(r'//[^/]+/[^/]+/[^/]+\s+([^:]+:[^:\s]+)', line)
    if credentials:
        return credentials.group(1)
    credentials = re.search(r'\s+([^:]+:[^:\s]+)', line)
    if credentials:
        return credentials.group(1)
    return None

def process_wg_regions(input_filename, output_dir, progress_var, stats_label, root):
    base_filename = os.path.splitext(os.path.basename(input_filename))[0]
    region_files = {
        'eu': open(os.path.join(output_dir, f'WG-EU_{base_filename}.txt'), 'a', encoding='utf-8'),
        'ru': open(os.path.join(output_dir, f'WG-RU_{base_filename}.txt'), 'a', encoding='utf-8'),
        'asia': open(os.path.join(output_dir, f'WG-ASIA_{base_filename}.txt'), 'a', encoding='utf-8'),
        'na': open(os.path.join(output_dir, f'WG-NA_{base_filename}.txt'), 'a', encoding='utf-8')
    }
    stats = {region: {'found': 0, 'loaded': 0} for region in region_files}
    try:
        total_lines = 0
        processed_lines = 0
        with open(input_filename, 'r', encoding='utf-8') as file:
            total_lines = sum(1 for _ in file)
        progress_var.set(0)
        root.update_idletasks()
        with open(input_filename, 'r', encoding='utf-8') as file:
            for line in file:
                processed_lines += 1
                line = line.strip()
                if '@' not in line:
                    continue
                credentials = extract_email_credentials(line)
                if not credentials:
                    continue
                if 'eu.' in line.lower():
                    stats['eu']['found'] += 1
                    region_files['eu'].write(credentials + '\n')
                    stats['eu']['loaded'] += 1
                elif 'ru.' in line.lower():
                    stats['ru']['found'] += 1
                    region_files['ru'].write(credentials + '\n')
                    stats['ru']['loaded'] += 1
                elif 'asia.' in line.lower():
                    stats['asia']['found'] += 1
                    region_files['asia'].write(credentials + '\n')
                    stats['asia']['loaded'] += 1
                elif 'na.' in line.lower():
                    stats['na']['found'] += 1
                    region_files['na'].write(credentials + '\n')
                    stats['na']['loaded'] += 1
                progress_var.set((processed_lines / total_lines) * 100)
                root.update_idletasks()
        stats_text = "\n".join(
            [f"Регион {region.upper()}: найдено {count['found']}, загружено {count['loaded']}" for region, count in stats.items()]
        )
        stats_label.config(text=f"Обработка завершена:\n{stats_text}")
    except Exception as e:
        stats_label.config(text=f"Ошибка: {str(e)}")
    finally:
        for file in region_files.values():
            file.close()
        progress_var.set(100)
        root.update_idletasks()

def start_wg_region_sorting(progress_var, stats_label, root):
    input_file = filedialog.askopenfilename(
        title="Выберите файл для сортировки по регионам WG",
        filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
    )
    if not input_file:
        stats_label.config(text="Файл не выбран")
        return
    output_dir = filedialog.askdirectory(title="Выберите папку для сохранения результатов")
    if not output_dir:
        stats_label.config(text="Папка для сохранения не выбрана")
        return
    stats_label.config(text="Сортировка по регионам WG начата...")
    root.update_idletasks()
    thread = threading.Thread(
        target=process_wg_regions,
        args=(input_file, output_dir, progress_var, stats_label, root),
        daemon=True
    )
    thread.start()

def create_ui():
    root = tk.Tk()
    root.title("ULP sorter by iA")
    root.geometry("700x900")
    root.resizable(False, False)

    style = ttk.Style()
    style.configure("TButton", font=("Arial", 10))
    style.configure("TLabel", font=("Arial", 10))
    style.configure("TEntry", font=("Arial", 10))

    input_file = tk.StringVar()
    output_dir = tk.StringVar()
    queries = tk.StringVar()
    progress_var = tk.DoubleVar()
    file_list = []

    def select_input_file():
        file_path = filedialog.askopenfilename(
            title="Выберите файл для обработки",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        input_file.set(file_path)

    def select_output_dir():
        folder_path = filedialog.askdirectory(title="Выберите папку для сохранения результатов")
        output_dir.set(folder_path)

    if os.path.exists("icon.jpg"):
        image = Image.open("icon.jpg")
        bg_image = ImageTk.PhotoImage(image)
        bg_label = tk.Label(root, image=bg_image)
        bg_label.place(relwidth=1, relheight=1)
        bg_label.image = bg_image

    ttk.Label(root, text="Выберите файл:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
    ttk.Entry(root, textvariable=input_file, width=50).grid(row=0, column=1, padx=5, pady=5)
    ttk.Button(root, text="Обзор", command=select_input_file).grid(row=0, column=2, padx=5, pady=5)

    ttk.Label(root, text="Выберите папку для сохранения:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
    ttk.Entry(root, textvariable=output_dir, width=50).grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(root, text="Обзор", command=select_output_dir).grid(row=1, column=2, padx=5, pady=5)

    ttk.Label(root, text="Введите запросы (через запятую):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
    ttk.Entry(root, textvariable=queries, width=50).grid(row=2, column=1, padx=5, pady=5)

    ttk.Button(
        root, text="Начать поиск запросов",
        command=lambda: start_filtering(input_file.get(), output_dir.get(), queries.get(), progress_var, stats_label, root)
    ).grid(row=3, column=1, pady=10)

    ttk.Button(
        root, text="Проверить почту",
        command=lambda: start_email_filtering(progress_var, stats_label, root)
    ).grid(row=4, column=1, pady=10)

    ttk.Button(
        root, text="Извлечь LOGIN:PASS",
        command=lambda: start_login_pass_extraction(progress_var, stats_label, root)
    ).grid(row=5, column=1, pady=10)

    ttk.Button(
        root, text="Удалить дубли",
        command=lambda: start_remove_duplicates(progress_var, stats_label, root)
    ).grid(row=6, column=1, pady=10)

    ttk.Button(
        root, text="Удалить GJN",
        command=lambda: start_remove_gjn(progress_var, stats_label, root)
    ).grid(row=7, column=1, pady=10)

    ttk.Button(
        root, text="TxT сортировка по алфавиту",
        command=lambda: start_sort_file(progress_var, stats_label, root)
    ).grid(row=8, column=1, pady=10)

    ttk.Label(root, text="Файлы для объединения:").grid(row=9, column=0, sticky="w")
    file_listbox = tk.Listbox(root, height=5, width=50)
    file_listbox.grid(row=9, column=1, padx=5, pady=5)

    ttk.Button(
        root, text="Добавить файл",
        command=lambda: add_file_to_merge(file_list, file_listbox, stats_label)
    ).grid(row=9, column=2, pady=5)

    ttk.Button(
        root, text="Объединить файлы",
        command=lambda: merge_files_ui(file_list, progress_var, stats_label, root)
    ).grid(row=10, column=1, pady=10)

    ttk.Button(
        root, text="Запрос из лога",
        command=lambda: start_query_from_logs(progress_var, stats_label, root)
    ).grid(row=11, column=1, pady=10)

    ttk.Button(
        root, text="Разделить файл",
        command=lambda: start_split_file(progress_var, stats_label, root)
    ).grid(row=12, column=1, pady=10)

    ttk.Button(
        root, text="Парсить ULP из логов",
        command=lambda: start_parse_ulp_from_logs(progress_var, stats_label, root)
    ).grid(row=13, column=1, pady=10)

    ttk.Button(
        root, text="WG регион",
        command=lambda: start_wg_region_sorting(progress_var, stats_label, root)
    ).grid(row=14, column=1, pady=10)

    progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
    progress_bar.grid(row=15, column=0, columnspan=3, sticky="we", padx=10, pady=10)

    stats_label = ttk.Label(root, text="Статистика:")
    stats_label.grid(row=16, column=0, columnspan=3, sticky="w", padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_ui()