# Caching_DNS_Server
Файл server.py при запуске на localhost, 53 запускает кэширующий DNS-сервер, который получает запрос на разрешение 
доменного имени в IP-адрес. В случае, если ответ на запрос есть в кэше, сервер отвечает клиенту данными из кэша.
В противном случае сервер обращается к удаленному авторитетному серверу, кэширует ответ и отправляет его клиенту.
При корректной остановке программы кэш записывается в файл при корневом катологе и восстанавливается при 
повторном запуске. При грубой остановке(KeyboardInterrupt) кэш также записывается в файл.

Ссылка на защиту: https://youtu.be/UCbLQVZBaSc
