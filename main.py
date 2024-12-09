import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import re

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException, ConnectionException
import threading

# Настройки подключения по умолчанию для ESR и MES
settings = {
    "ESR": {
        "host": "192.168.1.1",
        "username": "admin",
        "password": "admin",
        "secret": "",
        "device_type": "eltex",  # Для ESR (SSH)
    },
    "MES": {
        "host": "192.168.1.239",
        "username": "admin",
        "password": "admin",
        "secret": "",
        "device_type": "generic_termserver_telnet",  # Для MES (Telnet)
    },
}


# Основное окно
class ConfigApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eltex Configuration Tool")
        self.inputs = {"ESR": {}, "MES": {}}
        self.root.minsize(350, 250)  # Размер основного окна
        self.create_widgets()

    def create_widgets(self):
        # Создаем контейнер для ESR и MES
        esr_frame = tk.LabelFrame(self.root, text="ESR", padx=10, pady=10)
        esr_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        mes_frame = tk.LabelFrame(self.root, text="MES", padx=10, pady=10)
        mes_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Устанавливаем растягивание по оси X
        self.root.grid_columnconfigure(0, weight=1, uniform="equal")
        self.root.grid_columnconfigure(1, weight=1, uniform="equal")

        esr_frame.grid_columnconfigure(0, weight=1)
        mes_frame.grid_columnconfigure(0, weight=1)

        # Создаем кнопки в ESR и MES с растягиванием по оси X
        self.create_config_buttons(esr_frame, "ESR")
        self.create_config_buttons(mes_frame, "MES")

        # Кнопка настройки подключения
        tk.Button(self.root, text="Настройка подключения", command=self.open_connection_settings).grid(
            row=1, column=0, columnspan=2, pady=10, padx=5, sticky="ew"
        )

    def create_config_buttons(self, frame, device):
        tk.Button(frame, text="Базовый", command=lambda: self.apply_config(f"{device}_base.txt", device)).grid(
            row=0, column=0, pady=2, padx=0, sticky="ew", ipadx=5, ipady=5
        )
        tk.Button(frame, text="Заводской", command=lambda: self.factory_reset(device)).grid(
            row=1, column=0, pady=2, padx=0, sticky="ew", ipadx=5, ipady=5
        )
        tk.Button(frame, text="Пользовательский", command=lambda: self.upload_config(device)).grid(
            row=2, column=0, pady=2, padx=0, sticky="ew", ipadx=5, ipady=5
        )

    def open_connection_settings(self):
        # Окно настроек подключения
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Настройка подключения")

        # Настройка растягивания колонок и строк
        settings_window.grid_columnconfigure(0, weight=1)
        settings_window.grid_columnconfigure(1, weight=2)

        # Поля для ESR
        tk.Label(settings_window, text="ESR", font=("Arial", 10, "bold")).grid(row=0, column=0, columnspan=2, pady=5)
        self.create_connection_inputs(settings_window, "ESR", 1)

        # Поля для MES
        tk.Label(settings_window, text="MES", font=("Arial", 10, "bold")).grid(row=6, column=0, columnspan=2, pady=5)
        self.create_connection_inputs(settings_window, "MES", 7)

        def save_settings():
            # Сохранение настроек подключения
            for device in ["ESR", "MES"]:
                # Валидация значений
                if not self.validate_inputs(self.inputs[device]):
                    return

                # Сохранение настроек
                settings[device]["host"] = self.inputs[device]["host"].get()
                settings[device]["username"] = self.inputs[device]["username"].get()
                settings[device]["password"] = self.inputs[device]["password"].get()
                settings[device]["secret"] = self.inputs[device]["secret"].get()

            settings_window.destroy()
            messagebox.showinfo("Успех", "Настройки подключения сохранены!")

        # Кнопка сохранения
        tk.Button(settings_window, text="Сохранить", command=save_settings).grid(row=12, column=0, columnspan=2,
                                                                                 pady=10)

    def create_connection_inputs(self, window, device, start_row):
        # Убедимся, что в self.inputs есть запись для устройства
        if device not in self.inputs:
            self.inputs[device] = {}

        def create_input(label, key, row):
            tk.Label(window, text=label).grid(row=row, column=0, padx=10, pady=5, sticky="w")
            entry = tk.Entry(window)
            entry.insert(0, settings[device][key])  # Подставляем текущее значение из настроек
            entry.grid(row=row, column=1, padx=10, pady=5, sticky="ew")
            self.inputs[device][key] = entry  # Сохраняем ссылку на виджет ввода

        create_input("IP-адрес", "host", start_row)
        create_input("Логин", "username", start_row + 1)
        create_input("Пароль", "password", start_row + 2)
        create_input("Секрет", "secret", start_row + 3)

    def validate_inputs(self, inputs):
        # Проверка IP-адреса
        ip = inputs["host"].get()
        if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip) or not all(0 <= int(octet) <= 255 for octet in ip.split(".")):
            messagebox.showerror("Ошибка", f"Некорректный IP-адрес: {ip}")
            return False

        # Проверка логина
        username = inputs["username"].get()
        if not username.strip():
            messagebox.showerror("Ошибка", "Логин не может быть пустым.")
            return False

        # Проверка пароля
        password = inputs["password"].get()
        if not password.strip():
            messagebox.showerror("Ошибка", "Пароль не может быть пустым.")
            return False

        # Проверка секрета (если указан)
        secret = inputs["secret"].get()
        if secret and len(secret) < 3:
            messagebox.showerror("Ошибка", "Секрет должен содержать не менее 3 символов.")
            return False

        return True

    def apply_config(self, config_file, device):
        try:
            with open(config_file, "r") as file:
                commands = file.readlines()
            self.run_commands(device, commands)
        except FileNotFoundError:
            messagebox.showerror("Ошибка", f"Файл конфигурации {config_file} не найден.")

    def factory_reset(self, device):
        # Команда сброса к заводским настройкам
        factory_command = ["reset configuration factory-default"]
        self.run_commands(device, factory_command)

    def upload_config(self, device):
        # Загрузка пользовательской конфигурации
        file_path = filedialog.askopenfilename(title="Выберите файл конфигурации",
                                               filetypes=[("Текстовые файлы", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r") as file:
                    commands = file.readlines()
                self.run_commands(device, commands)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить конфигурацию: {e}")

    def run_commands(self, device, commands):
        def execute():
            output_window = tk.Toplevel(self.root)
            output_window.title("Результаты выполнения")

            output_area = scrolledtext.ScrolledText(output_window, width=80, height=20,
                                                    state="disabled")  # Только для чтения
            output_area.pack(padx=10, pady=10)

            try:
                connection = ConnectHandler(**settings[device])
                if settings[device]["secret"]:
                    connection.enable()

                # Выводим статус подключения
                output_area.config(state="normal")  # Временно разрешаем редактирование
                output_area.insert(tk.END, f"Подключение к {settings[device]['host']}...\n")
                output_area.config(state="disabled")  # Снова отключаем редактирование

                # Выполняем команды
                for command in commands:
                    result = connection.send_command(command.strip())
                    output_area.config(state="normal")
                    output_area.insert(tk.END, f"\n>>> {command.strip()}\n{result}\n")
                    output_area.config(state="disabled")

                connection.disconnect()

                # Выводим сообщение о закрытии соединения
                output_area.config(state="normal")
                output_area.insert(tk.END, "\nСоединение закрыто.\n")
                output_area.config(state="disabled")

            except NetmikoTimeoutException as e:
                # Ошибка подключения: тайм-аут
                output_area.config(state="normal")
                output_area.insert(tk.END, f"\nОшибка подключения к {device}: Тайм-аут при подключении. {e}\n")
                output_area.config(state="disabled")

            except NetmikoAuthenticationException as e:
                # Ошибка подключения: неверный логин/пароль
                output_area.config(state="normal")
                output_area.insert(tk.END, f"\nОшибка подключения к {device}: Ошибка аутентификации. {e}\n")
                output_area.config(state="disabled")

            except ConnectionException as e:
                # Общая ошибка подключения
                output_area.config(state="normal")
                output_area.insert(tk.END, f"\nОшибка подключения к {device}: {e}\n")
                output_area.config(state="disabled")

            except Exception as e:
                # Общая ошибка
                output_area.config(state="normal")
                output_area.insert(tk.END, f"\nОшибка: {e}\n")
                output_area.config(state="disabled")

            # Прокрутка до конца
            output_area.see(tk.END)

        # Выполнение команд в отдельном потоке
        threading.Thread(target=execute).start()


# Запуск приложения
if __name__ == "__main__":
    root = tk.Tk()
    app = ConfigApp(root)
    root.mainloop()

