
Для Linux
1) из 'Linux/C' скопировать libkalkancryptwr-64.so в /usr/lib/
из 'Linux/libs_for_linux' тоже копируем все библиотеки в /usr/lib/ причем списком без директорий.
Для проверки, что у libkalkancryptwr-64.so все впорядке с зависимостями используй эту команду   "ldd /usr/lib/libkalkancryptwr-64.so" , если там нету типа Not found чего то, то все в порядке


2) открываем 'Linux/ca-certs/.../readme.txt' и читаем


Для Windows
 устанавливаем корневые сертификаты из pki.gov.kz