# Сканер сетевых портов
Данная программа представляет собой **сканер сетевых портов**, способный определять открытые TCP и UDP порты на заданном хосте в заданном диапазоне. Код реализован на Python с использованием модулей `socket`, `Queue` и `threading` для обеспечения многопоточной работы.

## Структура кода
Код состоит из нескольких частей:

1. Определение функций для TCP и UDP сканирования
2. Функция `worker` для обработки портов
3. Функция для сканирования портов
4. Основная программа для взаимодействия с пользователем

## TCP сканирование
Функция `tcp_scan` создает TCP-сокет и устанавливает таймаут. Происходит подключение к указанному IP и порту. 

- Если соединение успешно, функция возвращает `True`.
- В случае таймаута или отказа в соединении возвращает `False`.
- При возникновении других ошибок выводит сообщение и также возвращает `False`.

После завершения работы сокет закрывается.

## UDP сканирование
Функция `udp_scan` создает UDP-сокет и устанавливает таймаут. 

- Отправляется пустое сообщение на указанный порт. 
- Если ответ не получен в течение таймаута, считается, что порт может быть открыт.
- Если получен ICMP-ответ о недоступности порта, функция возвращает `False`.

## Функция работника (worker)
Функция `worker` извлекает порты из очереди и выполняет сканирование в зависимости от указанного типа (TCP или UDP). Открытые порты добавляются в список результатов, и выводится сообщение о каждом открытом порте.


## Пример использования
1. Введите IP-адрес или домен: `example.com`  
   Начальный порт: `443`  
   Конечный порт: `443`  
   **Результаты:**  
   Открытые TCP-порты: `[443]`  
   Открытые UDP-порты: `[443]`  

2. Введите IP-адрес или домен: `scanme.nmap.org`  
   Начальный порт: `20`  
   Конечный порт: `85`  
   **Результаты:**  
   Открытые TCP-порты: `[22, 80]`  
   Открытые UDP-порты: `[20, 24, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 79, 80, 81, 82, 83, 84, 85]`
