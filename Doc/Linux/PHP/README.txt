Пример работы с основными функциями криптопровайдера в приложениях на PHP под ОС Linux.

Для успешного запуска примера test.php необходимо:
1) установить php на Ваш компьютер (7.0.8, или 7.2.28, или 7.3.3, или 7.4.2 )
2) в файле test.php изменить переменные: 
		- $container - путь к ключу *.p12; 
		- $password - пароль к сертификату;
		- $filePath - путь к сертификату *.cer;
3) скопировать файл kalkancrypt.so в PHP-store-lib;
4) в файле php.ini добавить строку: extension=kalkancrypt
5) пройти в папку SDK 2.0\C\Linux\libs_for_linux и скопировать папку kalkancrypt в каталог /opt/;
6) Установить корневые сертификаты из папки SDK 2.0\C\Linux\ca-certs ;
7) ввести команду в командной строке: 
		- export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/kalkancrypt/:/opt/kalkancrypt/lib/engines ;
		- php test.php.

