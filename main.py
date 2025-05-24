import json
import time
import hashlib
import math
from typing import Set, List, Tuple, Dict


class BloomFilter:
    """
    Реалізація фільтра Блума для ефективної перевірки належності елементів
    """
    
    def __init__(self, size: int, num_hashes: int):
        """
        Ініціалізація фільтра Блума
        
        Args:
            size: розмір бітового масиву
            num_hashes: кількість хеш-функцій
        """
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [False] * size
    
    def _hash(self, item: str, seed: int) -> int:
        """
        Генерує хеш для елемента з використанням заданого seed
        
        Args:
            item: елемент для хешування
            seed: початкове значення для хеш-функції
            
        Returns:
            Індекс в бітовому масиві
        """
        hash_input = f"{item}{seed}".encode('utf-8')
        hash_result = hashlib.md5(hash_input).hexdigest()
        return int(hash_result, 16) % self.size
    
    def add(self, item: str) -> None:
        """
        Додає елемент до фільтра
        
        Args:
            item: елемент для додавання
        """
        # Обробка некоректних значень
        if item is None:
            item = "None"
        elif not isinstance(item, str):
            item = str(item)
        
        # Встановлюємо біти для всіх хеш-функцій
        for i in range(self.num_hashes):
            index = self._hash(item, i)
            self.bit_array[index] = True
    
    def contains(self, item: str) -> bool:
        """
        Перевіряє, чи може елемент бути у фільтрі
        
        Args:
            item: елемент для перевірки
            
        Returns:
            True, якщо елемент може бути у фільтрі, False - якщо точно немає
        """
        # Обробка некоректних значень
        if item is None:
            item = "None"
        elif not isinstance(item, str):
            item = str(item)
        
        # Перевіряємо всі хеш-функції
        for i in range(self.num_hashes):
            index = self._hash(item, i)
            if not self.bit_array[index]:
                return False
        return True


def check_password_uniqueness(bloom_filter: BloomFilter, new_passwords: List[str]) -> Dict[str, str]:
    """
    Перевіряє унікальність нових паролів використовуючи фільтр Блума
    
    Args:
        bloom_filter: екземпляр фільтра Блума з існуючими паролями
        new_passwords: список нових паролів для перевірки
        
    Returns:
        Словник з результатами перевірки для кожного пароля
    """
    results = {}
    
    for password in new_passwords:
        # Обробка некоректних значень
        if password is None:
            password_str = "None"
        elif not isinstance(password, str):
            password_str = str(password)
        else:
            password_str = password
        
        # Перевірка через фільтр Блума
        if bloom_filter.contains(password_str):
            results[password_str] = "вже використаний"
        else:
            results[password_str] = "унікальний"
    
    return results


class HyperLogLog:
    """
    Реалізація алгоритму HyperLogLog для наближеного підрахунку унікальних елементів
    """
    
    def __init__(self, precision: int = 8):
        """
        Ініціалізація HyperLogLog
        
        Args:
            precision: точність (кількість бітів для визначення bucket)
        """
        self.precision = precision
        self.num_buckets = 2 ** precision
        self.buckets = [0] * self.num_buckets
        
        # Константи для корекції
        if self.num_buckets == 16:
            self.alpha = 0.673
        elif self.num_buckets == 32:
            self.alpha = 0.697
        elif self.num_buckets == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1 + 1.079 / self.num_buckets)
    
    def _hash(self, value: str) -> int:
        """
        Хешує значення за допомогою SHA-256
        
        Args:
            value: значення для хешування
            
        Returns:
            32-бітний хеш
        """
        return int(hashlib.sha256(value.encode('utf-8')).hexdigest()[:8], 16)
    
    def _leading_zeros(self, binary_str: str) -> int:
        """
        Підраховує кількість провідних нулів у бінарному рядку
        
        Args:
            binary_str: бінарний рядок
            
        Returns:
            Кількість провідних нулів + 1
        """
        count = 0
        for bit in binary_str:
            if bit == '0':
                count += 1
            else:
                break
        return count + 1
    
    def add(self, value: str) -> None:
        """
        Додає значення до HyperLogLog
        
        Args:
            value: значення для додавання
        """
        hash_val = self._hash(value)
        binary = format(hash_val, '032b')
        bucket_index = int(binary[:self.precision], 2)
        remaining_bits = binary[self.precision:]
        leading_zeros = self._leading_zeros(remaining_bits)
        self.buckets[bucket_index] = max(self.buckets[bucket_index], leading_zeros)
    
    def estimate(self) -> float:
        """
        Оцінює кількість унікальних елементів
        
        Returns:
            Оцінка кількості унікальних елементів
        """
        raw_estimate = self.alpha * (self.num_buckets ** 2) / sum(2 ** (-x) for x in self.buckets)
        
        # Корекція для малих значень
        if raw_estimate <= 2.5 * self.num_buckets:
            zeros = self.buckets.count(0)
            if zeros != 0:
                return self.num_buckets * math.log(self.num_buckets / zeros)
        
        # Корекція для великих значень
        if raw_estimate <= (1.0/30.0) * (2**32):
            return raw_estimate
        else:
            return -2**32 * math.log(1 - raw_estimate / 2**32)


def load_log_data(filename: str) -> List[str]:
    """
    Завантажує дані з лог-файлу та витягує IP-адреси
    
    Args:
        filename: шлях до файлу з логами
        
    Returns:
        Список IP-адрес
    """
    ip_addresses = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    log_entry = json.loads(line)
                    if 'remote_addr' in log_entry:
                        ip = log_entry['remote_addr']
                        if ip and isinstance(ip, str):
                            ip_addresses.append(ip)
                except json.JSONDecodeError:
                    # Ігноруємо некоректні рядки
                    continue
                except Exception:
                    continue
    
    except FileNotFoundError:
        print(f"Файл {filename} не знайдено")
        return []
    except Exception as e:
        print(f"Помилка читання файлу: {e}")
        return []
    
    return ip_addresses


def exact_count_unique_ips(ip_addresses: List[str]) -> Tuple[int, float]:
    """
    Точний підрахунок унікальних IP-адрес за допомогою set
    
    Args:
        ip_addresses: список IP-адрес
        
    Returns:
        Кортеж (кількість унікальних IP, час виконання)
    """
    start_time = time.time()
    unique_ips = set(ip_addresses)
    end_time = time.time()
    
    return len(unique_ips), end_time - start_time


def hyperloglog_count_unique_ips(ip_addresses: List[str], precision: int = 8) -> Tuple[float, float]:
    """
    Наближений підрахунок унікальних IP-адрес за допомогою HyperLogLog
    
    Args:
        ip_addresses: список IP-адрес
        precision: точність HyperLogLog
        
    Returns:
        Кортеж (оцінка кількості унікальних IP, час виконання)
    """
    start_time = time.time()
    hll = HyperLogLog(precision=precision)
    
    for ip in ip_addresses:
        hll.add(ip)
    
    estimate = hll.estimate()
    end_time = time.time()
    
    return estimate, end_time - start_time





def main():
    """
    Головна функція для демонстрації обох завдань
    """
    print("="*60)
    print("ДОМАШНЄ ЗАВДАННЯ: АЛГОРИТМИ РОБОТИ З ВЕЛИКИМИ ДАНИМИ")
    print("="*60)
    
    # ==================== ЗАВДАННЯ 1 ====================
    print("\nЗАВДАННЯ 1: Перевірка унікальності паролів за допомогою фільтра Блума")
    print("-" * 60)
    
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
    
    # ==================== ЗАВДАННЯ 2 ====================
    print("\nЗАВДАННЯ 2: Порівняння продуктивності HyperLogLog із точним підрахунком")
    print("-" * 60)
    
    # Перевіряємо наявність файлу логів
    import os
    if not os.path.exists("lms-stage-access.log"):
        print("ПОМИЛКА: Файл 'lms-stage-access.log' не знайдено!")
        return
    
    # Завантажуємо дані з реального файлу логів
    print("Завантаження даних з файлу lms-stage-access.log...")
    ip_addresses = load_log_data("lms-stage-access.log")
    
    if ip_addresses:
        print(f"Завантажено {len(ip_addresses)} записів з логів")
        
        # Точний підрахунок
        exact_count, exact_time = exact_count_unique_ips(ip_addresses)
        
        # HyperLogLog підрахунок
        hll_estimate, hll_time = hyperloglog_count_unique_ips(ip_addresses)
        
        # Виведення результатів у форматі таблиці
        print("\nРезультати порівняння:")
        print(f"{'':25} {'Точний підрахунок':>20} {'HyperLogLog':>15}")
        print(f"{'Унікальні елементи':25} {exact_count:>20.1f} {hll_estimate:>15.1f}")
        print(f"{'Час виконання (сек.)':25} {exact_time:>20.3f} {hll_time:>15.3f}")
        
        # Додаткова інформація
        error_rate = abs(hll_estimate - exact_count) / exact_count * 100
        speedup = exact_time / hll_time if hll_time > 0 else float('inf')
        print(f"\nПохибка HyperLogLog: {error_rate:.2f}%")
        print(f"Прискорення: {speedup:.2f}x")
    else:
        print("Не вдалося завантажити дані з лог-файлу")
    
    print("\n" + "="*60)
    print("="*60)


if __name__ == "__main__":
    main()